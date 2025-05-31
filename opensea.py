import json
import asyncio
import random

import pandas as pd
from datetime import datetime, timezone
from loguru import logger

from fake_useragent import UserAgent
from faker import Faker
from eth_account.account import Account
from curl_cffi.requests import AsyncSession, BrowserType
from tools.sol import SolAccount
from tools.evm import get_signature
from tools.twitter import Twitter, get_query_param
from tools.discord import Discord
from tools.nocaptcha import NoCaptcha
from settings import SyncNum, RandomWait, RandomSolToken, SolAmount, RerunIds


def async_retry(async_func):
    async def wrapper(*args, **kwargs):
        tries, delay = 5, 1.5
        while tries > 0:
            try:
                return await async_func(*args, **kwargs)
            except Exception:
                tries -= 1
                if tries <= 0:
                    raise
                await asyncio.sleep(delay)

                delay *= 2
                delay += random.uniform(0, 1)
                delay = min(delay, 10)

    return wrapper


class Opensea:
    def __init__(self, idx, private_key, sol_key, user_agent, proxy, twitter_token, discord_token):
        self.idx = idx
        self.account = Account.from_key(private_key)
        self.sol_account = SolAccount(sol_key)
        self.headers = {
            'accept': 'application/graphql-response+json, application/graphql+json, application/json, text/event-stream, multipart/mixed',
            'accept-language': 'zh-HK,zh-TW;q=0.9,zh;q=0.8',
            'content-type': 'application/json',
            'origin': 'https://opensea.io',
            'priority': 'u=1, i',
            'referer': 'https://opensea.io/',
            'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="124", "Google Chrome";v="124"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': user_agent,
            'x-app-id': 'os2-web'
        }
        self.proxy = proxy
        self.proxies = {
            "http": f"socks5://{proxy}",
            "https": f"socks5://{proxy}"
        }
        self.sess = AsyncSession(
            proxies=self.proxies,
            impersonate=BrowserType.chrome124,
            cookies={
                'os2AccessEx': 'Wdr6yywSUvHzIWYeBybn17MOdxKRbbhM',
                'auth_access_hint': 'true'
            }
        )
        self.os_base_url = 'https://gql.opensea.io/graphql'
        self.twitter = Twitter(twitter_token, proxy, user_agent)
        self.discord = Discord(idx, discord_token, user_agent, proxy)

    @async_retry
    async def solve_captcha(self):
        captcha = NoCaptcha()
        website = 'https://opensea.io'
        res = await captcha.solve_cloudflare(website, self.proxy)
        self.headers.update(res['extra'])
        cookies = res['data']['cookies']
        cookies_parts = cookies.split('cf_clearance=')
        self.sess.cookies.set('cf_clearance', cookies_parts[1], secure=True, domain='.opensea.io')

    async def get_nonce(self):
        headers = self.headers.copy()
        headers.update({
            'accept': '*/*',
        })
        headers.pop('content-type')
        headers.pop('x-app-id')

        response = await self.sess.post('https://opensea.io/__api/auth/siwe/nonce', headers=headers)

        if response.status_code != 200:
            logger.error(f'get nonce failed, status code: {response.status_code}')

        res = json.loads(response.text)
        return res['nonce']

    async def signin(self):
        headers = self.headers.copy()
        headers.update({
            'accept': '*/*',
        })
        headers.pop('x-app-id')

        nonce = await self.get_nonce()
        issue_at = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        message = f"opensea.io wants you to sign in with your account:\n{self.account.address}\n\nClick to sign in and accept the OpenSea Terms of Service (https://opensea.io/tos) and Privacy Policy (https://opensea.io/privacy).\n\nURI: https://opensea.io/zh-CN/rewards\nVersion: 1\nChain ID: 1\nNonce: {nonce}\nIssued At: {issue_at}"
        signature = get_signature(message, self.account.key)

        json_data = {
            'message': {
                'domain': 'opensea.io',
                'address': self.account.address,
                'statement': 'Click to sign in and accept the OpenSea Terms of Service (https://opensea.io/tos) and Privacy Policy (https://opensea.io/privacy).',
                'uri': 'https://opensea.io/zh-CN/rewards',
                'version': '1',
                'chainId': '1',
                'nonce': nonce,
                'issuedAt': issue_at,
            },
            'signature': signature,
            'chainArch': 'EVM',  # 'SVM',
        }

        response = await self.sess.post('https://opensea.io/__api/auth/siwe/verify', headers=headers,
                                        json=json_data)
        if response.status_code != 200:
            raise Exception(f"account {self.idx} login failed ❌")

        access_token = response.cookies.get("access_token", domain='.opensea.io')
        if access_token is None:
            raise Exception(f'account {self.idx} empty access_token')

        self.sess.cookies.set('access_token', access_token, secure=True, domain='.opensea.io')
        logger.success(f"account {self.idx} login success ✔")

        res = json.loads(response.text)
        return res['user']

    async def check_accept_terms(self):
        headers = self.headers.copy()

        json_data = {
            'operationName': 'TermsAcceptance',
            'query': 'query TermsAcceptance($address: Address!) {\n  profileByAddress(address: $address) {\n    ... on Profile {\n      hasAcceptedTerms\n      __typename\n    }\n    __typename\n  }\n}',
            'variables': {
                'address': self.account.address,
            },
        }

        response = await self.sess.post('https://gql.opensea.io/graphql', headers=headers, json=json_data)
        if response.status_code != 200:
            raise Exception(f"account {self.idx} check terms acceptance failed ❌")

        res = json.loads(response.text)
        return res['data']['profileByAddress']['hasAcceptedTerms']

    async def accept_terms(self):
        headers = self.headers.copy()

        json_data = {
            'operationName': 'AcceptTermsMutation',
            'query': 'mutation AcceptTermsMutation($address: Address!) {\n  acceptTerms(address: $address)\n}',
            'variables': {
                'address': self.account.address,
            },
        }

        response = await self.sess.post('https://gql.opensea.io/graphql', headers=headers,
                                        json=json_data)
        if response.status_code != 200:
            raise Exception(f"account {self.idx} accept terms failed ❌")

        logger.info(f"account {self.idx} accept terms success ✔")

    async def get_reward_sidebar(self):
        headers = self.headers.copy()
        headers.update({
            'x-query-signature': '71abc13b75cb752f86246df5eb111f5685c2dc438d1d399292df8ed09bd86aff'
        })

        json_data = {
            'operationName': 'RewardsSidebar',
            'query': 'query RewardsSidebar($address: Address!) {\n  rewardProfile(address: $address) {\n    ...RewardGroupUsers\n    ...RewardsStats\n    ...RewardBadges\n    loyalty\n    __typename\n  }\n}\nfragment RewardGroupUsers on RewardProfileResponse {\n  users {\n    address\n    twitterHandle\n    discordHandle\n    walletType\n    profile {\n      displayName\n      imageUrl\n      address\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\nfragment RewardsStats on RewardProfileResponse {\n  totalXP\n  loyalty\n  __typename\n}\nfragment RewardBadges on RewardProfileResponse {\n  badges {\n    ...BadgeChip\n    __typename\n  }\n  __typename\n}\nfragment BadgeChip on Badge {\n  name\n  description\n  imageUrl\n  ...BadgeSheet\n  __typename\n}\nfragment BadgeSheet on Badge {\n  id\n  name\n  description\n  imageUrl\n  __typename\n}',
            'variables': {
                'address': self.account.address.lower(),
            },
        }

        response = await self.sess.post('https://gql.opensea.io/graphql', headers=headers, json=json_data)
        if response.status_code != 200:
            raise Exception(f"account {self.idx} get reward sidebar failed ❌")

        res = json.loads(response.text)
        logger.info(f"account {self.idx} current XP: {res['data']['rewardProfile']['totalXP']} 🎉🎉🎉")
        return res['data']['rewardProfile']['users']

    async def reward_user(self):
        headers = self.headers.copy()
        headers.update({
            'x-query-signature': 'eed1e50f667cca967c538b26c1ee0b5ec721e8cd9648fc9f6802ad1372295c63'
        })

        json_data = {
            'operationName': 'RewardUser',
            'query': 'mutation RewardUser {\n  rewardUser {\n    success\n    __typename\n  }\n}',
            'variables': {},
        }

        response = await self.sess.post(self.os_base_url, headers=headers, json=json_data)
        if response.status_code != 200:
            raise Exception(f"account {self.idx} reward user error❌")

        res = json.loads(response.text)
        if res['data']['rewardUser']['success']:
            logger.info(f"account {self.idx} reward user success✔")
        else:
            raise Exception(f"account {self.idx} reward user failed❌")

    async def connect_twitter(self):
        headers = self.headers.copy()
        headers.update({
            'x-query-signature': '4109788e099daff021971b2c567dcf21962002dd5f93b51cfd4654a314fdf165'
        })

        json_data = {
            'operationName': 'ConnectTwitterButton',
            'query': 'query ConnectTwitterButton($redirectUrl: String!, $address: Address!) {\n  snagTwitterAuthUrl(redirectUrl: $redirectUrl, address: $address)\n}',
            'variables': {
                'address': self.account.address.lower(),
                'redirectUrl': 'https://opensea.io/rewards',
            },
        }

        response = await self.sess.post('https://gql.opensea.io/graphql', headers=headers,
                                        json=json_data)
        if response.status_code != 200:
            raise Exception(f"account {self.idx} get twitter auth url failed❌")

        res = json.loads(response.text)
        auth_url = res['data']['snagTwitterAuthUrl']

        await self.twitter.start()

        response_type = get_query_param(auth_url, 'response_type')
        client_id = get_query_param(auth_url, 'client_id')
        redirect_uri = get_query_param(auth_url, 'redirect_uri')
        scope = get_query_param(auth_url, 'scope')
        state = get_query_param(auth_url, 'state')
        code_challenge = get_query_param(auth_url, 'code_challenge')
        code_challenge_method = get_query_param(auth_url, 'code_challenge_method')

        await self.twitter.start()
        auth_code, _ = await self.twitter.oauth_v2(response_type, client_id, redirect_uri, scope, state, code_challenge,
                                                   code_challenge_method)

        await self.twitter_callback(auth_code, state)

    async def twitter_callback(self, auth_code, state):
        headers = self.headers.copy()
        headers.update({
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'referer': 'https://x.com/',
            'priority': 'u=0, i',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'cross-site',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
        })
        headers.pop('content-type')
        headers.pop('x-app-id')
        headers.pop('origin')

        params = {
            'state': state,
            'code': auth_code,
        }

        response = await self.sess.get(
            'https://opensea.io/rewards/oauth/api/twitter/auth/callback',
            params=params,
            headers=headers,
        )
        if response.status_code in [403, 404, 500, 502]:
            raise Exception(f"account {self.idx} twitter callback1 failed❌")

        await self.twitter_callback2(auth_code, state)

    async def twitter_callback2(self, auth_code, state):
        headers = self.headers.copy()
        headers.update({
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'referer': 'https://x.com/',
            'priority': 'u=0, i',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'cross-site',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
        })
        headers.pop('content-type')
        headers.pop('x-app-id')
        headers.pop('origin')

        params = {
            'state': state,
            'code': auth_code,
        }

        response = await self.sess.get('https://snag-render.com/api/twitter/auth/callback', params=params,
                                       headers=headers)
        if response.status_code in [403, 404, 500, 502]:
            raise Exception(f"account {self.idx} twitter callback2 failed❌")

        await self.sess.get(response.url, headers=headers)
        logger.info(f"account {self.idx} twitter connected success ✅✅✅")

    async def connect_discord(self):
        headers = self.headers.copy()
        headers.update({
            'x-query-signature': '9f6f219bc37a5c9b17290d13cd2c792da79155b628349c17c18f98274b73da9f'
        })

        json_data = {
            'operationName': 'ConnectDiscordButton',
            'query': 'query ConnectDiscordButton($redirectUrl: String!, $address: Address!) {\n  snagDiscordAuthUrl(redirectUrl: $redirectUrl, address: $address)\n}',
            'variables': {
                'address': self.account.address.lower(),
                'redirectUrl': 'https://opensea.io/rewards',
            },
        }

        response = await self.sess.post('https://gql.opensea.io/graphql', headers=headers, json=json_data)
        if response.status_code != 200:
            raise Exception(f"account {self.idx} get discord auth url failed❌")

        res = json.loads(response.text)
        auth_url = res['data']['snagDiscordAuthUrl']

        state = get_query_param(auth_url, 'state')
        params = {
            'client_id': get_query_param(auth_url, 'client_id'),
            'response_type': get_query_param(auth_url, 'response_type'),
            'redirect_uri': get_query_param(auth_url, 'redirect_uri'),
            'scope': get_query_param(auth_url, 'scope'),
            'state': state,
        }

        json_data = {
            'guild_id': '1334877877400895518',
            'permissions': '0',
            'authorize': True,
            'integration_type': 0,
            'location_context': {
                'guild_id': '10000',
                'channel_id': '10000',
                'channel_type': 10000,
            },
            'dm_settings': {
                'allow_mobile_push': False,
            },
        }

        auth_code = await self.discord.authorize(params, json_data)

        await self.discord_callback(auth_code, state)

    async def discord_callback(self, auth_code, state):
        headers = self.headers.copy()
        headers.update({
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'referer': 'https://discord.com/',
            'priority': 'u=0, i',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'cross-site',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
        })
        headers.pop('content-type')
        headers.pop('x-app-id')
        headers.pop('origin')

        params = {
            'code': auth_code,
            'state': state,
        }

        response = await self.sess.get(
            'https://opensea.io/rewards/oauth/api/discord/auth/callback',
            params=params,
            headers=headers,
        )
        if response.status_code in [403, 404, 500, 502]:
            raise Exception(f"account {self.idx} discord callback1 failed❌")

        await self.discord_callback2(auth_code, state)

    async def discord_callback2(self, auth_code, state):
        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'zh-HK,zh-TW;q=0.9,zh;q=0.8',
            'priority': 'u=0, i',
            'referer': 'https://discord.com/',
            'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'cross-site',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        }

        params = {
            'code': auth_code,
            'state': state,
        }

        response = await self.sess.get('https://snag-render.com/api/discord/auth/callback', params=params,
                                       headers=headers)
        if response.status_code in [403, 404, 500, 502]:
            raise Exception(f"account {self.idx} discord callback2 failed❌")

        await self.sess.get(response.url, headers=headers)
        logger.info(f"account {self.idx} discord connected success ✅✅✅")

    async def request_link_account(self):
        headers = self.headers.copy()
        headers.update({
            'x-query-signature': '2e9a2090f96e2b532a02629f3528d47418ed9de1d1e1c2833b518d96da8f905e'
        })

        json_data = {
            'operationName': 'RewardRequestAccountsLinking',
            'query': 'mutation RewardRequestAccountsLinking($address: Address!) {\n  requestAccountsLinking(address: $address) {\n    ... on RequestAccountsLinking {\n      issuedAt\n      message\n      __typename\n    }\n    __typename\n  }\n}',
            'variables': {
                'address': self.sol_account.keypair.pubkey().__str__(),
            },
        }

        response = await self.sess.post('https://gql.opensea.io/graphql', headers=headers,
                                        json=json_data)
        if response.status_code != 200:
            raise Exception(f'account {self.idx} get link account message failed ❌ ')

        res = json.loads(response.text)
        return res['data']['requestAccountsLinking']

    async def reward_link_account(self):
        headers = self.headers.copy()
        headers.update({
            'x-query-signature': '0efee48179dd618d2c6c9dfcee7ae0e3b08f551215a93b968b7b248835bdb66f'
        })

        link_message = await self.request_link_account()
        signature = self.sol_account.sign_sol_message(link_message['message'])

        json_data = {
            'operationName': 'RewardLinkAccounts',
            'query': 'mutation RewardLinkAccounts($address: Address!, $signature: String!, $issuedAt: DateTime!) {\n  linkAccounts(address: $address, signature: $signature, issuedAt: $issuedAt) {\n    ... on LinkAccountsResponse {\n      success\n      message\n      __typename\n    }\n    __typename\n  }\n}',
            'variables': {
                'address': self.sol_account.keypair.pubkey().__str__(),
                'issuedAt': link_message['issuedAt'],
                'signature': signature,
            },
        }

        response = await self.sess.post('https://gql.opensea.io/graphql', headers=headers,
                                        json=json_data)
        if response.status_code != 200:
            raise Exception(f"account {self.idx} link account failed ❌")

        res = json.loads(response.text)
        if not res['data']['linkAccounts']['success']:
            raise Exception(f"account {self.idx} link account failed ❌ | {res['data']['linkAccounts']['message']}")

        logger.success(f"account {self.idx} link solana account success ✅")

    async def get_user_gallery(self):
        headers = self.headers.copy()
        headers.update({
            'x-query-signature': '94446977c4e1d102bccdd3f0545e09ccab9819142d346dc0a01070849e2a071b',
        })

        json_data = {
            'operationName': 'ProfileFeaturedGalleries',
            'query': 'query ProfileFeaturedGalleries($address: Address!) {\n  profileShelvesByAddress(address: $address) {\n    ...galleryList\n    __typename\n  }\n}\nfragment galleryList on ProfileShelf {\n  id\n  title\n  description\n  items {\n    id\n    imageUrl\n    tokenId\n    chain {\n      identifier\n      __typename\n    }\n    contractAddress\n    __typename\n  }\n  icon\n  view\n  singleItemShelfSide\n  ...GallerySection\n  __typename\n}\nfragment GallerySection on ProfileShelf {\n  ...SingleItemGallery\n  ...MultiItemGallery\n  items {\n    __typename\n  }\n  __typename\n}\nfragment SingleItemGallery on ProfileShelf {\n  id\n  title\n  description\n  items {\n    __typename\n    ...ItemMedia\n    ...ItemLink\n  }\n  icon\n  singleItemShelfSide\n  __typename\n}\nfragment ItemMedia on Item {\n  imageUrl\n  animationUrl\n  backgroundColor\n  collection {\n    imageUrl\n    __typename\n  }\n  __typename\n}\nfragment ItemLink on BaseItem {\n  ...itemUrl\n  chain {\n    identifier\n    __typename\n  }\n  tokenId\n  contractAddress\n  imageUrl\n  animationUrl\n  ...useSetItemQuickView\n  __typename\n}\nfragment itemUrl on ItemIdentifier {\n  chain {\n    identifier\n    arch\n    __typename\n  }\n  tokenId\n  contractAddress\n  __typename\n}\nfragment useSetItemQuickView on Item {\n  ...itemUrl\n  ...ItemViewModal\n  __typename\n}\nfragment ItemViewModal on Item {\n  tokenId\n  imageUrl\n  id\n  name\n  ...itemIdentifier\n  ...ItemViewSkeleton\n  ...itemUrl\n  __typename\n}\nfragment itemIdentifier on ItemIdentifier {\n  chain {\n    identifier\n    __typename\n  }\n  tokenId\n  contractAddress\n  __typename\n}\nfragment ItemViewSkeleton on Item {\n  name\n  ...ItemPageMedia\n  ...ItemTabs\n  ...ItemAbout\n  __typename\n}\nfragment ItemPageMedia on Item {\n  ...ItemMedia\n  __typename\n}\nfragment ItemTabs on Item {\n  isFungible\n  collection {\n    slug\n    __typename\n  }\n  __typename\n}\nfragment ItemAbout on Item {\n  id\n  name\n  tokenId\n  tokenUri\n  contractAddress\n  chain {\n    name\n    identifier\n    arch\n    __typename\n  }\n  standard\n  description\n  details {\n    name\n    value\n    __typename\n  }\n  collection {\n    ...CollectionOwner\n    name\n    description\n    owner {\n      displayName\n      ...AccountLockup\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\nfragment CollectionOwner on Collection {\n  owner {\n    displayName\n    isVerified\n    address\n    ...profileUrl\n    ...ProfilePreviewTooltip\n    __typename\n  }\n  standard\n  __typename\n}\nfragment profileUrl on ProfileIdentifier {\n  address\n  __typename\n}\nfragment ProfilePreviewTooltip on ProfileIdentifier {\n  address\n  ...ProfilePreviewTooltipContent\n  __typename\n}\nfragment ProfilePreviewTooltipContent on ProfileIdentifier {\n  address\n  __typename\n}\nfragment AccountLockup on ProfileIdentifier {\n  address\n  displayName\n  imageUrl\n  ...profileUrl\n  __typename\n}\nfragment MultiItemGallery on ProfileShelf {\n  id\n  title\n  description\n  items {\n    id\n    __typename\n    ...ProfileItemsCardFragment\n  }\n  icon\n  view\n  __typename\n}\nfragment ProfileItemsCardFragment on Item {\n  id\n  isFungible\n  chain {\n    identifier\n    __typename\n  }\n  contractAddress\n  tokenId\n  ...bestItemOffer\n  lowestListingForOwner(address: $address) {\n    id\n    pricePerItem {\n      ...TokenPrice\n      __typename\n    }\n    maker {\n      address\n      __typename\n    }\n    marketplace {\n      identifier\n      __typename\n    }\n    ...useCancelOrders\n    __typename\n  }\n  owner {\n    address\n    __typename\n  }\n  enforcement {\n    isDisabled\n    isCompromised\n    __typename\n  }\n  collection {\n    name\n    slug\n    isVerified\n    ...CollectionLink\n    ...CollectionPreviewTooltip\n    __typename\n  }\n  ...useBuyItems\n  ...useMakeOffer\n  ...useListItems\n  ...profileItemsSelection\n  ...useAcceptOffers\n  ...QuantityBadge\n  ...ItemCardMedia\n  ...ItemCardNameFragment\n  ...RarityBadgeFragment\n  ...ItemLink\n  ...OwnedQuantity\n  ...EnforcementBadge\n  ...useCancelItemsListings\n  ...ItemOwnedQuantity\n  ...isItemTradable\n  __typename\n}\nfragment ItemCardMedia on Item {\n  id\n  tokenId\n  ...ItemMedia\n  __typename\n}\nfragment ItemCardNameFragment on Item {\n  name\n  __typename\n}\nfragment RarityBadgeFragment on Item {\n  rarity {\n    rank\n    category\n    __typename\n  }\n  ...RarityTooltip\n  ...isItemRarityDisabled\n  __typename\n}\nfragment RarityTooltip on Item {\n  rarity {\n    category\n    rank\n    totalSupply\n    __typename\n  }\n  ...isItemRarityDisabled\n  __typename\n}\nfragment isItemRarityDisabled on Item {\n  collection {\n    id\n    slug\n    __typename\n  }\n  __typename\n}\nfragment TokenPrice on Price {\n  usd\n  token {\n    unit\n    symbol\n    contractAddress\n    chain {\n      identifier\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\nfragment useBuyItems on Item {\n  chain {\n    identifier\n    arch\n    __typename\n  }\n  contractAddress\n  tokenId\n  collection {\n    slug\n    isTradingDisabled\n    __typename\n  }\n  bestListing {\n    pricePerItem {\n      token {\n        unit\n        address\n        symbol\n        ...currencyIdentifier\n        __typename\n      }\n      __typename\n    }\n    maker {\n      address\n      __typename\n    }\n    __typename\n  }\n  ...isItemListed\n  ...isItemTradable\n  __typename\n}\nfragment isItemListed on Item {\n  bestListing {\n    __typename\n  }\n  __typename\n}\nfragment isItemTradable on Item {\n  collection {\n    isTradingDisabled\n    __typename\n  }\n  enforcement {\n    isCompromised\n    isDisabled\n    __typename\n  }\n  isTradingDisabled\n  __typename\n}\nfragment currencyIdentifier on ContractIdentifier {\n  contractAddress\n  chain {\n    identifier\n    __typename\n  }\n  __typename\n}\nfragment useMakeOffer on Item {\n  tokenId\n  chain {\n    identifier\n    arch\n    __typename\n  }\n  contractAddress\n  ...isItemTradable\n  __typename\n}\nfragment profileItemsSelection on Item {\n  id\n  imageUrl\n  chain {\n    identifier\n    __typename\n  }\n  contractAddress\n  tokenId\n  bestOffer {\n    __typename\n  }\n  bestListing {\n    maker {\n      address\n      __typename\n    }\n    __typename\n  }\n  collection {\n    slug\n    __typename\n  }\n  lowestListingForOwner(address: $address) {\n    __typename\n  }\n  isFungible\n  ...useTransferItems\n  ...useAcceptOffers\n  ...useListItems\n  ...useCancelItemsListings\n  ...isItemTradable\n  ...HideButton\n  __typename\n}\nfragment useTransferItems on Item {\n  tokenId\n  chain {\n    identifier\n    arch\n    __typename\n  }\n  contractAddress\n  ...ItemOwnedQuantity\n  ...isItemTradable\n  __typename\n}\nfragment ItemOwnedQuantity on Item {\n  ownership(address: $address) {\n    id\n    quantity\n    __typename\n  }\n  __typename\n}\nfragment useAcceptOffers on Item {\n  chain {\n    identifier\n    arch\n    __typename\n  }\n  contractAddress\n  tokenId\n  collection {\n    isTradingDisabled\n    __typename\n  }\n  bestOffer {\n    pricePerItem {\n      token {\n        unit\n        address\n        __typename\n      }\n      __typename\n    }\n    maker {\n      address\n      __typename\n    }\n    __typename\n  }\n  enforcement {\n    isCompromised\n    __typename\n  }\n  __typename\n}\nfragment useListItems on Item {\n  tokenId\n  chain {\n    identifier\n    arch\n    __typename\n  }\n  collection {\n    isTradingDisabled\n    __typename\n  }\n  contractAddress\n  ...ItemOwnedQuantity\n  ...isItemTradable\n  __typename\n}\nfragment useCancelItemsListings on Item {\n  chain {\n    arch\n    identifier\n    __typename\n  }\n  contractAddress\n  tokenId\n  lowestListingForOwner(address: $address) {\n    __typename\n  }\n  __typename\n}\nfragment HideButton on Item {\n  ownership(address: $address) {\n    id\n    isHidden\n    __typename\n  }\n  __typename\n}\nfragment OwnedQuantity on Item {\n  ...ItemOwnedQuantity\n  __typename\n}\nfragment EnforcementBadge on EnforcedEntity {\n  __typename\n  enforcement {\n    isCompromised\n    isDisabled\n    isOwnershipDisputed\n    __typename\n  }\n}\nfragment QuantityBadge on Item {\n  bestListing {\n    quantityRemaining\n    __typename\n  }\n  totalSupply\n  __typename\n}\nfragment CollectionLink on CollectionIdentifier {\n  slug\n  __typename\n}\nfragment useCancelOrders on BaseOrder {\n  id\n  marketplace {\n    identifier\n    __typename\n  }\n  maker {\n    address\n    __typename\n  }\n  __typename\n}\nfragment bestItemOffer on Item {\n  bestItemOffer {\n    pricePerItem {\n      native {\n        unit\n        __typename\n      }\n      ...TokenPrice\n      __typename\n    }\n    maker {\n      address\n      __typename\n    }\n    __typename\n  }\n  collection {\n    id\n    topOffer {\n      pricePerItem {\n        native {\n          unit\n          __typename\n        }\n        ...TokenPrice\n        __typename\n      }\n      maker {\n        address\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\nfragment CollectionPreviewTooltip on CollectionIdentifier {\n  ...CollectionPreviewTooltipContent\n  __typename\n}\nfragment CollectionPreviewTooltipContent on CollectionIdentifier {\n  slug\n  __typename\n}',
            'variables': {
                'address': self.account.address.lower(),
            },
        }

        response = await self.sess.post('https://gql.opensea.io/graphql', headers=headers, json=json_data)
        if response.status_code != 200:
            raise Exception(f"account {self.idx} get user gallery failed ❌")

        res = json.loads(response.text)
        if not res['data']['profileShelvesByAddress']:
            return False

        return True

    async def get_user_item_list(self):
        headers = self.headers.copy()
        headers.update({
            'x-query-signature': '6d7f65a1d36cdba7e8a723c0b70af101727e7b9ce93316c15a51cc0f93f2c123',
        })

        json_data = {
            'operationName': 'ProfileItemsListQuery',
            'query': 'query ProfileItemsListQuery($address: Address!, $limit: Int, $cursor: String, $sort: ProfileItemsSort!, $filter: ProfileItemsFilter) {\n  profileItems(\n    addresses: [$address]\n    limit: $limit\n    sort: $sort\n    filter: $filter\n    cursor: $cursor\n  ) {\n    nextPageCursor\n    items {\n      version\n      id\n      collection {\n        id\n        slug\n        __typename\n      }\n      enforcement {\n        isDelisted\n        __typename\n      }\n      isFungible\n      tokenId\n      contractAddress\n      ...ItemOwnedQuantity\n      lastTransferAt\n      ownership(address: $address) {\n        id\n        isHidden\n        __typename\n      }\n      chain {\n        identifier\n        __typename\n      }\n      bestListing {\n        startTime\n        maker {\n          address\n          __typename\n        }\n        __typename\n      }\n      bestOffer {\n        pricePerItem {\n          usd\n          __typename\n        }\n        __typename\n      }\n      lowestListingForOwner(address: $address) {\n        pricePerItem {\n          usd\n          __typename\n        }\n        __typename\n      }\n      ...ProfileItemsTableRowFragment\n      ...ProfileItemsCardFragment\n      ...profileItemsSelection\n      ...ProfileItemPaginator\n      __typename\n    }\n    __typename\n  }\n}\nfragment ProfileItemsTableRowFragment on Item {\n  id\n  chain {\n    ...ChainBadge\n    __typename\n  }\n  isFungible\n  name\n  lastTransferAt\n  ownership(address: $address) {\n    id\n    __typename\n  }\n  rarity {\n    rank\n    category\n    __typename\n  }\n  collection {\n    floorPrice {\n      pricePerItem {\n        ...TokenPrice\n        __typename\n      }\n      __typename\n    }\n    name\n    isVerified\n    ...CollectionLink\n    ...CollectionPreviewTooltip\n    __typename\n  }\n  enforcement {\n    isCompromised\n    __typename\n  }\n  lowestListingForOwner(address: $address) {\n    pricePerItem {\n      ...TokenPrice\n      __typename\n    }\n    __typename\n  }\n  lastSale {\n    ...TokenPrice\n    __typename\n  }\n  standard\n  ...SellItemTableButton\n  ...ItemLink\n  ...ItemAvatar\n  ...profileItemsSelection\n  ...EnforcementBadge\n  ...OwnedQuantity\n  ...RarityTooltip\n  ...isItemRarityDisabled\n  ...ItemPreviewTooltip\n  ...BulkActionsDisabledTooltip\n  __typename\n}\nfragment ChainBadge on Chain {\n  identifier\n  name\n  __typename\n}\nfragment ItemLink on BaseItem {\n  ...itemUrl\n  chain {\n    identifier\n    __typename\n  }\n  tokenId\n  contractAddress\n  imageUrl\n  animationUrl\n  ...useSetItemQuickView\n  __typename\n}\nfragment itemUrl on ItemIdentifier {\n  chain {\n    identifier\n    arch\n    __typename\n  }\n  tokenId\n  contractAddress\n  __typename\n}\nfragment useSetItemQuickView on Item {\n  ...itemUrl\n  ...ItemViewModal\n  __typename\n}\nfragment ItemViewModal on Item {\n  tokenId\n  imageUrl\n  id\n  name\n  ...itemIdentifier\n  ...ItemViewSkeleton\n  ...itemUrl\n  __typename\n}\nfragment itemIdentifier on ItemIdentifier {\n  chain {\n    identifier\n    __typename\n  }\n  tokenId\n  contractAddress\n  __typename\n}\nfragment ItemViewSkeleton on Item {\n  name\n  ...ItemPageMedia\n  ...ItemTabs\n  ...ItemAbout\n  __typename\n}\nfragment ItemPageMedia on Item {\n  ...ItemMedia\n  __typename\n}\nfragment ItemMedia on Item {\n  imageUrl\n  animationUrl\n  backgroundColor\n  collection {\n    imageUrl\n    __typename\n  }\n  __typename\n}\nfragment ItemTabs on Item {\n  isFungible\n  collection {\n    slug\n    __typename\n  }\n  __typename\n}\nfragment ItemAbout on Item {\n  id\n  name\n  tokenId\n  tokenUri\n  contractAddress\n  chain {\n    name\n    identifier\n    arch\n    __typename\n  }\n  standard\n  description\n  details {\n    name\n    value\n    __typename\n  }\n  collection {\n    ...CollectionOwner\n    name\n    description\n    owner {\n      displayName\n      ...AccountLockup\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\nfragment CollectionOwner on Collection {\n  owner {\n    displayName\n    isVerified\n    address\n    ...profileUrl\n    ...ProfilePreviewTooltip\n    __typename\n  }\n  standard\n  __typename\n}\nfragment profileUrl on ProfileIdentifier {\n  address\n  __typename\n}\nfragment ProfilePreviewTooltip on ProfileIdentifier {\n  address\n  ...ProfilePreviewTooltipContent\n  __typename\n}\nfragment ProfilePreviewTooltipContent on ProfileIdentifier {\n  address\n  __typename\n}\nfragment AccountLockup on ProfileIdentifier {\n  address\n  displayName\n  imageUrl\n  ...profileUrl\n  __typename\n}\nfragment TokenPrice on Price {\n  usd\n  token {\n    unit\n    symbol\n    contractAddress\n    chain {\n      identifier\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\nfragment profileItemsSelection on Item {\n  id\n  imageUrl\n  chain {\n    identifier\n    __typename\n  }\n  contractAddress\n  tokenId\n  bestOffer {\n    __typename\n  }\n  bestListing {\n    maker {\n      address\n      __typename\n    }\n    __typename\n  }\n  collection {\n    slug\n    __typename\n  }\n  lowestListingForOwner(address: $address) {\n    __typename\n  }\n  isFungible\n  ...useTransferItems\n  ...useAcceptOffers\n  ...useListItems\n  ...useCancelItemsListings\n  ...isItemTradable\n  ...HideButton\n  __typename\n}\nfragment useTransferItems on Item {\n  tokenId\n  chain {\n    identifier\n    arch\n    __typename\n  }\n  contractAddress\n  ...ItemOwnedQuantity\n  ...isItemTradable\n  __typename\n}\nfragment ItemOwnedQuantity on Item {\n  ownership(address: $address) {\n    id\n    quantity\n    __typename\n  }\n  __typename\n}\nfragment isItemTradable on Item {\n  collection {\n    isTradingDisabled\n    __typename\n  }\n  enforcement {\n    isCompromised\n    isDisabled\n    __typename\n  }\n  isTradingDisabled\n  __typename\n}\nfragment useAcceptOffers on Item {\n  chain {\n    identifier\n    arch\n    __typename\n  }\n  contractAddress\n  tokenId\n  collection {\n    isTradingDisabled\n    __typename\n  }\n  bestOffer {\n    pricePerItem {\n      token {\n        unit\n        address\n        __typename\n      }\n      __typename\n    }\n    maker {\n      address\n      __typename\n    }\n    __typename\n  }\n  enforcement {\n    isCompromised\n    __typename\n  }\n  __typename\n}\nfragment useListItems on Item {\n  tokenId\n  chain {\n    identifier\n    arch\n    __typename\n  }\n  collection {\n    isTradingDisabled\n    __typename\n  }\n  contractAddress\n  ...ItemOwnedQuantity\n  ...isItemTradable\n  __typename\n}\nfragment useCancelItemsListings on Item {\n  chain {\n    arch\n    identifier\n    __typename\n  }\n  contractAddress\n  tokenId\n  lowestListingForOwner(address: $address) {\n    __typename\n  }\n  __typename\n}\nfragment HideButton on Item {\n  ownership(address: $address) {\n    id\n    isHidden\n    __typename\n  }\n  __typename\n}\nfragment ItemAvatar on Item {\n  imageUrl\n  tokenId\n  backgroundColor\n  collection {\n    imageUrl\n    __typename\n  }\n  __typename\n}\nfragment EnforcementBadge on EnforcedEntity {\n  __typename\n  enforcement {\n    isCompromised\n    isDisabled\n    isOwnershipDisputed\n    __typename\n  }\n}\nfragment OwnedQuantity on Item {\n  ...ItemOwnedQuantity\n  __typename\n}\nfragment RarityTooltip on Item {\n  rarity {\n    category\n    rank\n    totalSupply\n    __typename\n  }\n  ...isItemRarityDisabled\n  __typename\n}\nfragment isItemRarityDisabled on Item {\n  collection {\n    id\n    slug\n    __typename\n  }\n  __typename\n}\nfragment CollectionLink on CollectionIdentifier {\n  slug\n  __typename\n}\nfragment SellItemTableButton on Item {\n  ...bestItemOffer\n  ...useAcceptOffers\n  __typename\n}\nfragment bestItemOffer on Item {\n  bestItemOffer {\n    pricePerItem {\n      native {\n        unit\n        __typename\n      }\n      ...TokenPrice\n      __typename\n    }\n    maker {\n      address\n      __typename\n    }\n    __typename\n  }\n  collection {\n    id\n    topOffer {\n      pricePerItem {\n        native {\n          unit\n          __typename\n        }\n        ...TokenPrice\n        __typename\n      }\n      maker {\n        address\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\nfragment ItemPreviewTooltip on ItemIdentifier {\n  ...ItemPreviewTooltipContent\n  __typename\n}\nfragment ItemPreviewTooltipContent on ItemIdentifier {\n  ...itemIdentifier\n  __typename\n}\nfragment CollectionPreviewTooltip on CollectionIdentifier {\n  ...CollectionPreviewTooltipContent\n  __typename\n}\nfragment CollectionPreviewTooltipContent on CollectionIdentifier {\n  slug\n  __typename\n}\nfragment BulkActionsDisabledTooltip on Item {\n  collection {\n    slug\n    __typename\n  }\n  __typename\n}\nfragment ProfileItemsCardFragment on Item {\n  id\n  isFungible\n  chain {\n    identifier\n    __typename\n  }\n  contractAddress\n  tokenId\n  ...bestItemOffer\n  lowestListingForOwner(address: $address) {\n    id\n    pricePerItem {\n      ...TokenPrice\n      __typename\n    }\n    maker {\n      address\n      __typename\n    }\n    marketplace {\n      identifier\n      __typename\n    }\n    ...useCancelOrders\n    __typename\n  }\n  owner {\n    address\n    __typename\n  }\n  enforcement {\n    isDisabled\n    isCompromised\n    __typename\n  }\n  collection {\n    name\n    slug\n    isVerified\n    ...CollectionLink\n    ...CollectionPreviewTooltip\n    __typename\n  }\n  ...useBuyItems\n  ...useMakeOffer\n  ...useListItems\n  ...profileItemsSelection\n  ...useAcceptOffers\n  ...QuantityBadge\n  ...ItemCardMedia\n  ...ItemCardNameFragment\n  ...RarityBadgeFragment\n  ...ItemLink\n  ...OwnedQuantity\n  ...EnforcementBadge\n  ...useCancelItemsListings\n  ...ItemOwnedQuantity\n  ...isItemTradable\n  __typename\n}\nfragment ItemCardMedia on Item {\n  id\n  tokenId\n  ...ItemMedia\n  __typename\n}\nfragment ItemCardNameFragment on Item {\n  name\n  __typename\n}\nfragment RarityBadgeFragment on Item {\n  rarity {\n    rank\n    category\n    __typename\n  }\n  ...RarityTooltip\n  ...isItemRarityDisabled\n  __typename\n}\nfragment useBuyItems on Item {\n  chain {\n    identifier\n    arch\n    __typename\n  }\n  contractAddress\n  tokenId\n  collection {\n    slug\n    isTradingDisabled\n    __typename\n  }\n  bestListing {\n    pricePerItem {\n      token {\n        unit\n        address\n        symbol\n        ...currencyIdentifier\n        __typename\n      }\n      __typename\n    }\n    maker {\n      address\n      __typename\n    }\n    __typename\n  }\n  ...isItemListed\n  ...isItemTradable\n  __typename\n}\nfragment isItemListed on Item {\n  bestListing {\n    __typename\n  }\n  __typename\n}\nfragment currencyIdentifier on ContractIdentifier {\n  contractAddress\n  chain {\n    identifier\n    __typename\n  }\n  __typename\n}\nfragment useMakeOffer on Item {\n  tokenId\n  chain {\n    identifier\n    arch\n    __typename\n  }\n  contractAddress\n  ...isItemTradable\n  __typename\n}\nfragment QuantityBadge on Item {\n  bestListing {\n    quantityRemaining\n    __typename\n  }\n  totalSupply\n  __typename\n}\nfragment useCancelOrders on BaseOrder {\n  id\n  marketplace {\n    identifier\n    __typename\n  }\n  maker {\n    address\n    __typename\n  }\n  __typename\n}\nfragment ProfileItemPaginator on Item {\n  id\n  createdAt\n  rarity {\n    rank\n    __typename\n  }\n  collection {\n    floorPrice {\n      pricePerItem {\n        usd\n        __typename\n      }\n      __typename\n    }\n    topOffer {\n      pricePerItem {\n        usd\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  bestListing {\n    startTime\n    pricePerItem {\n      usd\n      __typename\n    }\n    __typename\n  }\n  bestOffer {\n    pricePerItem {\n      usd\n      __typename\n    }\n    __typename\n  }\n  lastSaleAt\n  lastSale {\n    usd\n    __typename\n  }\n  lastTransferAt\n  ownership(address: $address) {\n    id\n    __typename\n  }\n  lowestListingForOwner(address: $address) {\n    pricePerItem {\n      usd\n      __typename\n    }\n    __typename\n  }\n  __typename\n}',
            'variables': {
                'address': self.account.address.lower(),
                'limit': 50,
                'sort': {
                    'by': 'RECEIVED_DATE',
                    'direction': 'DESC',
                },
            },
        }

        response = await self.sess.post('https://gql.opensea.io/graphql', headers=headers,
                                        json=json_data)
        if response.status_code != 200:
            raise Exception(f"account {self.idx} get user nft item list failed ❌")

        res = json.loads(response.text)
        return res['data']['profileItems']['items']

    async def get_user_collection_list(self):
        headers = self.headers.copy()
        headers.update({
            'x-query-signature': '4bcafcc64e377c42e277fa4b6dfb696e5d6a0662c5f538e0630a7915eae13da6',
        })

        json_data = {
            'operationName': 'ProfileCollectionsListQuery',
            'query': 'query ProfileCollectionsListQuery($address: Address!, $cursor: String, $limit: Int, $filter: ProfileCollectionsFilter) {\n  profileCollections(\n    addresses: [$address]\n    cursor: $cursor\n    limit: $limit\n    filter: $filter\n  ) {\n    items {\n      id\n      ownership {\n        id\n        itemCount\n        totalQuantity\n        value {\n          usd\n          __typename\n        }\n        __typename\n      }\n      collection {\n        id\n        slug\n        name\n        __typename\n      }\n      ...ProfileCollectionsListRow\n      __typename\n    }\n    nextPageCursor\n    __typename\n  }\n}\nfragment ProfileCollectionsListRow on ProfileCollection {\n  id\n  ownership {\n    id\n    totalQuantity\n    value {\n      ...Volume\n      __typename\n    }\n    __typename\n  }\n  collection {\n    id\n    name\n    slug\n    isVerified\n    imageUrl\n    ...CollectionImage\n    __typename\n  }\n  __typename\n}\nfragment CollectionImage on Collection {\n  name\n  imageUrl\n  chain {\n    ...ChainBadge\n    __typename\n  }\n  __typename\n}\nfragment ChainBadge on Chain {\n  identifier\n  name\n  __typename\n}\nfragment Volume on Volume {\n  usd\n  native {\n    symbol\n    unit\n    __typename\n  }\n  __typename\n}',
            'variables': {
                'address': self.account.address.lower(),
                'filter': {},
                'limit': 100,
            },
        }

        response = await self.sess.post('https://gql.opensea.io/graphql', headers=headers, json=json_data)
        if response.status_code != 200:
            raise Exception(f"account {self.idx} get user nft collection list failed ❌")

        res = json.loads(response.text)
        return res['data']['profileCollections']['items']

    @async_retry
    async def query_quests(self):
        headers = self.headers.copy()
        headers.update({
            'x-query-signature': '1b3ee909efe7dae8ac56ec50eeffa9eccb1436138a82b7a1ce3e11b1d47ee7f4'
        })

        json_data = {
            'operationName': 'QuestsQuery',
            'query': 'query QuestsQuery($address: Address!) {\n  userQuests(address: $address) {\n    quest {\n      createdAt\n      id\n      type\n      tier\n      __typename\n    }\n    isComplete\n    ...VoyageCard\n    __typename\n  }\n}\nfragment VoyageCard on UserQuest {\n  quest {\n    id\n    name\n    description\n    expirationDate\n    ctaUrl\n    ctaText\n    amount\n    tier\n    type\n    chain {\n      ...ChainChip\n      __typename\n    }\n    requireCheckCompletion\n    showProgress\n    imageUrl\n    ...VoyageXPBadge\n    __typename\n  }\n  progress\n  isReadyToClaim\n  isComplete\n  completedActivity {\n    eventTime\n    __typename\n  }\n  badge {\n    name\n    description\n    imageUrl\n    __typename\n  }\n  __typename\n}\nfragment ChainChip on Chain {\n  identifier\n  name\n  __typename\n}\nfragment VoyageXPBadge on Quest {\n  amount\n  imageUrl\n  tier\n  __typename\n}',
            'variables': {
                'address': self.account.address.lower(),
            },
        }

        response = await self.sess.post('https://gql.opensea.io/graphql', headers=headers,
                                        json=json_data)
        if response.status_code != 200:
            raise Exception(f"account {self.idx} get quests failed 💢💢💢")

        res = json.loads(response.text)
        return res['data']['userQuests']

    async def create_gallery(self, items, title):
        headers = self.headers.copy()
        headers.update({
            'x-query-signature': '9564a5a08ec9eca4a7f61d10490c6a39bc81476687ca1048897398d28465b628'
        })

        json_data = {
            'operationName': 'CreateProfileShelfMutation',
            'query': 'mutation CreateProfileShelfMutation($input: CreateProfileShelfInput!) {\n  createProfileShelf(input: $input) {\n    success\n    error {\n      __typename\n    }\n    __typename\n  }\n}',
            'variables': {
                'input': {
                    'description': '',
                    'items': items,
                    'title': title,
                },
            },
        }

        response = await self.sess.post('https://gql.opensea.io/graphql', headers=headers,
                                        json=json_data)
        if response.status_code != 200:
            raise Exception(f"account {self.idx} create gallery failed ❌")

        res = response.json()
        if not res["data"]["createProfileShelf"]["success"]:
            raise Exception(f"account {self.idx} create gallery failed ❌")

        logger.success(f"account {self.idx} create profile gallery ✅✅✅")

    async def complete_quest(self, quest_id):
        headers = self.headers.copy()
        headers.update({
            'x-query-signature': 'e46ad77779bc0ebd56488b254b0e5e3072233931b39dc3333cfc531ded74309c'
        })

        json_data = {
            'operationName': 'completeQuest',
            'query': 'mutation completeQuest($questId: String!) {\n  completeQuest(questId: $questId) {\n    success\n    message\n    __typename\n  }\n}',
            'variables': {
                'questId': quest_id,
            },
        }

        response = await self.sess.post('https://gql.opensea.io/graphql', headers=headers,
                                        json=json_data)
        if response.status_code != 200:
            raise Exception(f"account {self.idx} complete quest failed ❌")

        res = response.json()
        if not res:
            logger.warning(f"account {self.idx} complete quest failed ❌ | {res['data']['completeQuest']['message']}")
            return False
        else:
            logger.success(f"account {self.idx} complete quest success ✔ ｜ {res['data']['completeQuest']['message']}")
            return True

    async def query_top_currency_stats(self):
        headers = self.headers.copy()
        headers.update({
            'x-query-signature': 'c0c18e1c5a662bb6289262f0e5232b2e3f4bfb55269d2ac3c64543b0093362c0'
        })

        json_data = {
            'operationName': 'TopCurrencyStatsTableQuery',
            'query': 'query TopCurrencyStatsTableQuery($cursor: String, $sort: CurrenciesSort!, $filter: CurrenciesFilter!, $limit: Int!) {\n  topCurrencies(cursor: $cursor, sort: $sort, filter: $filter, limit: $limit) {\n    items {\n      id\n      name\n      __typename\n      ...CurrencyStatsTableRow\n    }\n    nextPageCursor\n    __typename\n  }\n}\nfragment CurrencyStatsTableRow on Currency {\n  ...CurrencyStatsTableRowFDV\n  ...CurrencyStatsTableRowMarketCap\n  ...CurrencyStatsTableRowPrice\n  ...CurrencyStatsTableRowOneHourPriceChange\n  ...CurrencyStatsTableRowOneDayPriceChange\n  ...CurrencyStatsTableRowThirtyDayPriceChange\n  ...CurrencyStatsTableRowSupply\n  ...CurrencyStatsTableRowCollection\n  ...CurrencyStatsTableRowVolume\n  ...CurrencyLink\n  ...CurrencyStatsTableRowSparkLineChart\n  __typename\n}\nfragment CurrencyStatsTableRowFDV on Currency {\n  stats {\n    fdvUsd\n    __typename\n  }\n  __typename\n}\nfragment CurrencyStatsTableRowMarketCap on Currency {\n  stats {\n    marketCapUsd\n    __typename\n  }\n  __typename\n}\nfragment CurrencyStatsTableRowPrice on Currency {\n  ...CurrencyPrice\n  __typename\n}\nfragment CurrencyPrice on Currency {\n  usdPrice\n  __typename\n}\nfragment CurrencyStatsTableRowOneHourPriceChange on Currency {\n  stats {\n    oneHour {\n      priceChange\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\nfragment CurrencyStatsTableRowOneDayPriceChange on Currency {\n  stats {\n    oneDay {\n      priceChange\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\nfragment CurrencyStatsTableRowThirtyDayPriceChange on Currency {\n  stats {\n    thirtyDay {\n      priceChange\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\nfragment CurrencyStatsTableRowSupply on Currency {\n  stats {\n    marketCapUsd\n    fdvUsd\n    __typename\n  }\n  __typename\n}\nfragment CurrencyStatsTableRowCollection on Currency {\n  ...CurrencyImage\n  ...CurrencyLockup\n  collections {\n    id\n    __typename\n  }\n  __typename\n}\nfragment CurrencyImage on Currency {\n  imageUrl\n  chain {\n    ...ChainBadge\n    __typename\n  }\n  ...currencyIdentifier\n  __typename\n}\nfragment ChainBadge on Chain {\n  identifier\n  name\n  __typename\n}\nfragment currencyIdentifier on ContractIdentifier {\n  contractAddress\n  chain {\n    identifier\n    __typename\n  }\n  __typename\n}\nfragment CurrencyLockup on Currency {\n  name\n  symbol\n  ...CollectionCurrencyPreview\n  ...NewCurrencyChip\n  __typename\n}\nfragment CollectionCurrencyPreview on Currency {\n  ...CollectionCurrencyPreviewSheet\n  collections {\n    slug\n    ...collectionUrl\n    ...CollectionImage\n    ...CollectionPreviewTooltip\n    __typename\n  }\n  __typename\n}\nfragment collectionUrl on CollectionIdentifier {\n  slug\n  __typename\n}\nfragment CollectionImage on Collection {\n  name\n  imageUrl\n  chain {\n    ...ChainBadge\n    __typename\n  }\n  __typename\n}\nfragment CollectionPreviewTooltip on CollectionIdentifier {\n  ...CollectionPreviewTooltipContent\n  __typename\n}\nfragment CollectionPreviewTooltipContent on CollectionIdentifier {\n  slug\n  __typename\n}\nfragment CollectionCurrencyPreviewSheet on Currency {\n  collections {\n    ...CollectionPreviewTooltipContent\n    ...collectionUrl\n    __typename\n  }\n  __typename\n}\nfragment NewCurrencyChip on Currency {\n  genesisDate\n  ...isRecentlyCreated\n  __typename\n}\nfragment isRecentlyCreated on Currency {\n  genesisDate\n  __typename\n}\nfragment CurrencyStatsTableRowVolume on Currency {\n  stats {\n    oneDay {\n      volume\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\nfragment CurrencyLink on Currency {\n  chain {\n    identifier\n    __typename\n  }\n  contractAddress\n  ...currencyUrl\n  __typename\n}\nfragment currencyUrl on Currency {\n  chain {\n    identifier\n    __typename\n  }\n  contractAddress\n  __typename\n}\nfragment CurrencyStatsTableRowSparkLineChart on Currency {\n  ...CurrencySparkLineChart\n  __typename\n}\nfragment CurrencySparkLineChart on Currency {\n  sparkLineSevenDay {\n    price {\n      usd\n      __typename\n    }\n    time\n    __typename\n  }\n  __typename\n}',
            'variables': {
                'filter': {
                    'chains': [
                        'solana',
                    ],
                },
                'limit': 50,
                'sort': {
                    'by': 'ONE_DAY_PRICE_CHANGE',
                    'direction': 'DESC',
                },
            },
        }

        response = await self.sess.post('https://gql.opensea.io/graphql', headers=headers,
                                        json=json_data)
        if response.status_code != 200:
            raise Exception(f"account {self.idx} get top currency stats failed 💢💢💢")

        res = json.loads(response.text)
        return res['data']['topCurrencies']['items']

    async def get_swap_quote(self, sol_amount, dst_token):
        headers = self.headers.copy()

        json_data = {
            'operationName': 'useSwapQuote',
            'query': 'query useSwapQuote($fromAssets: [AssetQuantityInput!]!, $toAssets: [AssetQuantityInput!]!, $address: Address!, $slippageTolerance: Float!) {\n  swapQuote(\n    fromAssets: $fromAssets\n    toAssets: $toAssets\n    address: $address\n    slippageTolerance: $slippageTolerance\n  ) {\n    swapRoutes {\n      __typename\n      ... on SwapRoute {\n        swapProvider\n        toQuantity\n        fromQuantity\n        toAsset {\n          __typename\n          ... on Currency {\n            decimals\n            __typename\n          }\n          ...CurrencyIdentifier\n        }\n        fromAsset {\n          ... on Currency {\n            decimals\n            __typename\n          }\n          ...CurrencyIdentifier\n          __typename\n        }\n        pricePerFromAsset {\n          usd\n          __typename\n        }\n        pricePerToAsset {\n          usd\n          __typename\n        }\n        __typename\n      }\n    }\n    ...SwapDetails\n    ...useTrackSwapSuccess\n    __typename\n  }\n}\nfragment SwapDetails on SwapQuote {\n  swapRoutes {\n    ...SwapDetailsCollapsedItem\n    ...SwapDetailsProviderItem\n    ...SwapDetailsProviderFeeItem\n    ...SwapDetailsGasFeeItem\n    ...SwapDetailsEstimatedDurationItem\n    ...SwapDetailsNetworkItem\n    __typename\n  }\n  ...SwapDetailsMaxSlippageItem\n  __typename\n}\nfragment SwapDetailsCollapsedItem on SwapRouteResult {\n  ...useSwapCurrencies\n  ... on SwapRoute {\n    fromAsset {\n      ...CurrencyIdentifier\n      __typename\n    }\n    toAsset {\n      ...CurrencyIdentifier\n      __typename\n    }\n    costs {\n      costType\n      cost {\n        usd\n        __typename\n      }\n      __typename\n    }\n    pricePerFromAsset {\n      token {\n        unit\n        __typename\n      }\n      __typename\n    }\n    pricePerToAsset {\n      token {\n        unit\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\nfragment CurrencyIdentifier on Currency {\n  contractAddress\n  chain {\n    identifier\n    __typename\n  }\n  __typename\n}\nfragment useSwapCurrencies on SwapRouteResult {\n  ... on SwapRoute {\n    fromAsset {\n      ...ContextCurrency\n      __typename\n    }\n    toAsset {\n      ...ContextCurrency\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\nfragment ContextCurrency on Currency {\n  contractAddress\n  usdPrice\n  stats {\n    marketCapUsd\n    oneDay {\n      priceChange\n      __typename\n    }\n    __typename\n  }\n  symbol\n  decimals\n  name\n  imageUrl\n  chain {\n    identifier\n    __typename\n  }\n  isSwapDisabled\n  __typename\n}\nfragment SwapDetailsProviderItem on SwapRouteResult {\n  ... on SwapRoute {\n    swapProvider\n    __typename\n  }\n  __typename\n}\nfragment SwapDetailsProviderFeeItem on SwapRouteResult {\n  ...useSwapCurrencies\n  ... on SwapRoute {\n    pricePerFromAsset {\n      usd\n      token {\n        chain {\n          arch\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    costs {\n      costType\n      cost {\n        usd\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\nfragment SwapDetailsGasFeeItem on SwapRouteResult {\n  ... on SwapRoute {\n    costs {\n      costType\n      cost {\n        usd\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\nfragment SwapDetailsEstimatedDurationItem on SwapRouteResult {\n  ... on SwapRoute {\n    estimatedDurationMs\n    __typename\n  }\n  __typename\n}\nfragment SwapDetailsMaxSlippageItem on SwapQuote {\n  slippageTolerance\n  __typename\n}\nfragment SwapDetailsNetworkItem on SwapRouteResult {\n  ...useSwapCurrencies\n  __typename\n}\nfragment useTrackSwapSuccess on SwapQuote {\n  swapRoutes {\n    ... on SwapRoute {\n      fromAsset {\n        ... on Currency {\n          symbol\n          contractAddress\n          chain {\n            identifier\n            __typename\n          }\n          usdPrice\n          decimals\n          __typename\n        }\n        __typename\n      }\n      toAsset {\n        ... on Currency {\n          symbol\n          contractAddress\n          chain {\n            identifier\n            __typename\n          }\n          usdPrice\n          decimals\n          __typename\n        }\n        __typename\n      }\n      fromQuantity\n      toQuantity\n      swapProvider\n      __typename\n    }\n    __typename\n  }\n  __typename\n}',
            'variables': {
                'address': self.sol_account.keypair.pubkey().__str__(),
                'fromAssets': [
                    {
                        'asset': {
                            'chain': 'solana',
                            'contractAddress': '11111111111111111111111111111111',
                        },
                        'quantity': str(sol_amount),
                    },
                ],
                'slippageTolerance': 5,
                'toAssets': [
                    {
                        'asset': {
                            'chain': 'solana',
                            'contractAddress': dst_token,
                        },
                    },
                ],
            },
        }

        response = await self.sess.post('https://gql.opensea.io/graphql', headers=headers,
                                        json=json_data)
        if response.status_code != 200:
            raise Exception(f"account {self.idx} get swap quote failed ❌")

        res = json.loads(response.text)
        return res['data']['swapQuote']

    async def query_balance(self):
        headers = self.headers.copy()

        json_data = {
            'operationName': 'BalancesQuery',
            'query': 'query BalancesQuery($address: Address!) {\n  addressBalances(address: $address) {\n    ...ContextBalance\n    __typename\n  }\n}\nfragment ContextBalance on Balance {\n  id\n  currency {\n    id\n    contractAddress\n    chain {\n      identifier\n      minOfferPriceUsd\n      __typename\n    }\n    usdPrice\n    symbol\n    imageUrl\n    name\n    decimals\n    ...ContextCurrency\n    __typename\n  }\n  quantity\n  usdValue\n  __typename\n}\nfragment ContextCurrency on Currency {\n  contractAddress\n  usdPrice\n  stats {\n    marketCapUsd\n    oneDay {\n      priceChange\n      __typename\n    }\n    __typename\n  }\n  symbol\n  decimals\n  name\n  imageUrl\n  chain {\n    identifier\n    __typename\n  }\n  isSwapDisabled\n  __typename\n}',
            'variables': {
                'address': self.sol_account.keypair.pubkey().__str__(),
            },
        }

        response = await self.sess.post('https://gql.opensea.io/graphql', headers=headers,
                                        json=json_data)

        if response.status_code != 200:
            raise Exception(f"account {self.idx} get wallet balance failed❌")

        res = json.loads(response.text)

        return res['data']['addressBalances']

    async def use_swap(self, sol_amount, dst_token):
        headers = self.headers.copy()

        json_data = {
            'operationName': 'useSwap',
            'query': 'query useSwap($fromAssets: [AssetQuantityInput!]!, $toAssets: [AssetQuantityInput!]!, $address: Address!, $slippageTolerance: Float!, $recipient: Address!) {\n  swap(\n    fromAssets: $fromAssets\n    toAssets: $toAssets\n    address: $address\n    slippageTolerance: $slippageTolerance\n    recipient: $recipient\n  ) {\n    errors {\n      __typename\n    }\n    actions {\n      ...ActionTimeline\n      __typename\n    }\n    __typename\n  }\n}\nfragment ActionTimeline on BlockchainAction {\n  __typename\n  ...useScheduler_action\n  ...ActionTimelineItem\n}\nfragment useScheduler_action on BlockchainAction {\n  __typename\n  ... on BlurAuthAction {\n    chain {\n      identifier\n      __typename\n    }\n    expiresOn\n    hmac\n    signatureRequest {\n      message\n      ...useScheduler_signatureRequest\n      __typename\n    }\n    __typename\n  }\n  ... on RefreshAction {\n    message\n    __typename\n  }\n  ... on SignatureRequestAction {\n    signatureRequest {\n      ...useScheduler_signatureRequest\n      __typename\n    }\n    __typename\n  }\n  ... on TransactionAction {\n    transactionSubmissionData {\n      chain {\n        networkId\n        identifier\n        blockExplorer {\n          name\n          transactionUrlTemplate\n          __typename\n        }\n        __typename\n      }\n      ...useScheduler_transactionSubmissionData\n      __typename\n    }\n    __typename\n  }\n  ... on SvmTransactionAction {\n    svmTransactionSubmissionData {\n      ...useScheduler_svmTransactionSubmissionData\n      __typename\n    }\n    __typename\n  }\n  ... on GaslessCancelOrdersAction {\n    signatureRequest {\n      ...useScheduler_signatureRequest\n      __typename\n    }\n    __typename\n  }\n  ... on CrossChainCapableAction {\n    isCrossChain\n    __typename\n  }\n  ...useScheduler_readShouldBufferGas\n}\nfragment useScheduler_signatureRequest on SignatureRequest {\n  __typename\n  message\n  ... on SignTypedDataRequest {\n    chain {\n      networkId\n      __typename\n    }\n    __typename\n  }\n}\nfragment useScheduler_transactionSubmissionData on TransactionSubmissionData {\n  to\n  data\n  value\n  chain {\n    networkId\n    __typename\n  }\n  __typename\n}\nfragment useScheduler_svmTransactionSubmissionData on SvmTransactionSubmissionData {\n  instructions {\n    programId\n    data\n    keys {\n      pubkey\n      isSigner\n      isWritable\n      __typename\n    }\n    __typename\n  }\n  addressLookupTableAddresses\n  __typename\n}\nfragment useScheduler_readShouldBufferGas on BlockchainAction {\n  __typename\n  ... on SwapAssetsAction {\n    isCrossChain\n    __typename\n  }\n  ... on TransactionAction {\n    transactionSubmissionData {\n      chain {\n        identifier\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\nfragment ActionTimelineItem on BlockchainAction {\n  ... on BuyItemAction {\n    __typename\n    items {\n      imageUrl\n      id\n      __typename\n    }\n  }\n  ... on AcceptOfferAction {\n    __typename\n    items {\n      id\n      __typename\n    }\n  }\n  ... on ItemApprovalAction {\n    __typename\n    item {\n      collection {\n        name\n        imageUrl\n        __typename\n      }\n      __typename\n    }\n  }\n  ... on PaymentApprovalAction {\n    __typename\n    currency {\n      id\n      symbol\n      __typename\n    }\n  }\n  ... on CreateListingsAction {\n    items {\n      id\n      __typename\n    }\n    __typename\n  }\n  ... on UnwrapAction {\n    __typename\n    transactionSubmissionData {\n      to\n      chain {\n        identifier\n        nativeCurrency {\n          symbol\n          __typename\n        }\n        wrappedNativeCurrency {\n          symbol\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n  }\n  ... on WrapAction {\n    __typename\n    transactionSubmissionData {\n      to\n      chain {\n        identifier\n        nativeCurrency {\n          symbol\n          __typename\n        }\n        wrappedNativeCurrency {\n          symbol\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n  }\n  ... on MintAction {\n    __typename\n    collection {\n      imageUrl\n      __typename\n    }\n  }\n  __typename\n}',
            'variables': {
                'address': self.sol_account.keypair.pubkey().__str__(),
                'fromAssets': [
                    {
                        'asset': {
                            'chain': 'solana',
                            'contractAddress': '11111111111111111111111111111111',
                        },
                        'quantity': str(sol_amount),
                    },
                ],
                'recipient': self.sol_account.keypair.pubkey().__str__(),
                'slippageTolerance': 5,
                'toAssets': [
                    {
                        'asset': {
                            'chain': 'solana',
                            'contractAddress': dst_token,
                        },
                    },
                ],
            },
        }

        response = await self.sess.post('https://gql.opensea.io/graphql', headers=headers,
                                        json=json_data)
        if response.status_code != 200:
            raise Exception(f"account {self.idx} use swap failed❌")

        res = json.loads(response.text)

        if res['data']['swap']['errors']:
            raise Exception(f"account {self.idx} use swap error: {res['data']['swap']['errors'][0]}")

        return res['data']['swap']['actions'][0]['svmTransactionSubmissionData']

    async def use_swap_receipt(self, sol_amount, dst_token, dst_quantity, tx_hash):
        headers = self.headers.copy()

        json_data = {
            'operationName': 'useSwapReceipt',
            'query': 'query useSwapReceipt($transactionIdentifiers: [TransactionIdentifierSwapProvider!]!, $swapQuote: SwapAssetQuoteInput!) {\n  swapReceipt(\n    transactionIdentifiers: $transactionIdentifiers\n    swapQuote: $swapQuote\n  ) {\n    status\n    failReason\n    crossChainRefunded\n    assetReceipts {\n      fromAsset {\n        __typename\n        ... on Currency {\n          ...ContextCurrency\n          __typename\n        }\n      }\n      fromQuantity\n      toAsset {\n        __typename\n        ... on Currency {\n          ...ContextCurrency\n          __typename\n        }\n      }\n      toQuantity\n      __typename\n    }\n    failedAssetReceipts {\n      fromAsset {\n        ... on Currency {\n          ...ContextCurrency\n          __typename\n        }\n        __typename\n      }\n      fromQuantity\n      toAsset {\n        ... on Currency {\n          ...ContextCurrency\n          __typename\n        }\n        __typename\n      }\n      toQuantity\n      __typename\n    }\n    ...SwapStatus\n    __typename\n  }\n}\nfragment SwapStatus on SwapReceipt {\n  status\n  assetReceipts {\n    fromAsset {\n      ... on Currency {\n        ...CurrencyIdentifier\n        __typename\n      }\n      __typename\n    }\n    fromQuantity\n    toAsset {\n      ... on Currency {\n        ...CurrencyIdentifier\n        __typename\n      }\n      __typename\n    }\n    toQuantity\n    __typename\n  }\n  __typename\n}\nfragment CurrencyIdentifier on Currency {\n  contractAddress\n  chain {\n    identifier\n    __typename\n  }\n  __typename\n}\nfragment ContextCurrency on Currency {\n  contractAddress\n  usdPrice\n  stats {\n    marketCapUsd\n    oneDay {\n      priceChange\n      __typename\n    }\n    __typename\n  }\n  symbol\n  decimals\n  name\n  imageUrl\n  chain {\n    identifier\n    __typename\n  }\n  isSwapDisabled\n  __typename\n}',
            'variables': {
                'swapQuote': {
                    'fromAssets': [
                        {
                            'asset': {
                                'chain': 'solana',
                                'contractAddress': '11111111111111111111111111111111',
                            },
                            'quantity': str(sol_amount),
                        },
                    ],
                    'toAssets': [
                        {
                            'asset': {
                                'chain': 'solana',
                                'contractAddress': dst_token,
                            },
                            'quantity': str(dst_quantity),
                        },
                    ],
                },
                'transactionIdentifiers': [
                    {
                        'swapProvider': 'RELAY',
                        'transactionIdentifier': {
                            'chain': 'solana',
                            'transactionHash': tx_hash,
                        },
                    },
                ],
            },
        }

        response = await self.sess.post('https://gql.opensea.io/graphql', headers=headers,
                                        json=json_data)
        if response.status_code != 200:
            raise Exception(f'account {self.idx} use swap recipient failed ❌')

        res = json.loads(response.text)
        if res['data']['swapReceipt']['status'] == 'SUCCESS':
            return True

        return False

    async def execute_create_gallery(self):
        has_gallery = await self.get_user_gallery()
        if not has_gallery:
            item_list = await self.get_user_item_list()
            if len(item_list) == 0:
                logger.warning(f"account {self.idx} has no nft items, go to buy some! Dumb ass 🤡🤡")
                return
            elif len(item_list) <= 5:
                choose_num = 1
            else:
                choose_num = random.randint(1, 5)
            random_items = random.sample(item_list, choose_num)
            items = []
            for random_item in random_items:
                items.append({
                    'chain': random_item['chain']['identifier'],
                    'contractAddress': random_item['contractAddress'],
                    'tokenId': random_item['tokenId']
                })
            fake = Faker()
            title = fake.user_name()
            await self.create_gallery(items, title)
        else:
            logger.info(f"account {self.idx} already created a gallery")

    async def execute_purchase_on_solana(self):
        top_currencies = await self.query_top_currency_stats()

        if RandomSolToken:
            dst_token = random.choice(top_currencies)['contractAddress']
        else:
            dst_token = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'  # UDSC

        if SolAmount == 0:
            sol_amount = random.choice([0.04, 0.045, 0.05, 0.055, 0.06, 0.065, 0.07])
        else:
            sol_amount = SolAmount

        address_balances = await self.query_balance()
        sol_balance = next(
            item['quantity'] for item in address_balances
            if item['currency']['contractAddress'] == '11111111111111111111111111111111'
        )
        if float(sol_balance) < sol_amount:
            raise Exception(f'account {self.idx} sol balance is not enough ❌')

        swap_quote = await self.get_swap_quote(sol_amount, dst_token)

        to_quantity = swap_quote['swapRoutes'][0]['toQuantity']
        dst_decimals = swap_quote['swapRoutes'][0]['toAsset']['decimals']
        dst_quantity = float(to_quantity) / pow(10, dst_decimals)

        svm_transaction_data = await self.use_swap(sol_amount, dst_token)

        tx_hash = await self.sol_account.solana_trade(svm_transaction_data['instructions'],
                                                      svm_transaction_data['addressLookupTableAddresses'])

        swap_success = await self.use_swap_receipt(sol_amount, dst_token, dst_quantity, tx_hash)
        if swap_success:
            logger.success(
                f"account {self.idx} swap {sol_amount}SOL to {swap_quote['swapRoutes'][0]['toAsset']['symbol']} success ✅")

        else:
            raise Exception(
                f"account {self.idx} swap {sol_amount}SOL to {swap_quote['swapRoutes'][0]['toAsset']['symbol']} failed ❌")

    async def claim_reward(self, quest_id, quest_name):
        try_times = 5
        while try_times > 0:
            try:
                success = await self.complete_quest(quest_id)
                if not success:
                    await asyncio.sleep(5)
                else:
                    return True
            except Exception as e:
                logger.error(f"account {self.idx} complete quest {quest_name} error:{e}")
                continue
        return False

    async def execute_retweet(self, twitter_url):
        tweet_id = twitter_url.split('/')[-1]
        await self.twitter.retweet(tweet_id)
        logger.success(f"account {self.idx} retweet {twitter_url} success✅")

    async def execute_opensea_odyssey(self):
        await self.solve_captcha()
        await self.signin()

        is_accept_terms = await self.check_accept_terms()
        if not is_accept_terms:
            await self.accept_terms()
        await self.reward_user()

        user_info = await self.get_reward_sidebar()
        if not user_info[0]['twitterHandle']:
            await self.connect_twitter()

        if not user_info[0]['discordHandle']:
            await self.connect_discord()

        if len(user_info) == 1 and user_info[0]['walletType'] == 'EVM':
            await self.reward_link_account()

        quests = await self.query_quests()
        for quest in quests:
            quest_id = quest['quest']['id']
            quest_name = quest['quest']['name']
            try:
                if quest['isComplete']:
                    continue
                if quest['isReadyToClaim']:
                    claimed = await self.claim_reward(quest_id, quest_name)
                    if not claimed:
                        logger.error(f'account {self.idx} claim {quest_name} reward failed ❌')
                    continue
                if quest_name == 'Create or edit an OpenSea gallery':
                    await self.execute_create_gallery()
                    await asyncio.sleep(10)
                elif quest_name == 'Purchase $5 of any token on Solana':
                    await self.execute_purchase_on_solana()
                elif quest_name == 'Like and repost Launch Announcement':
                    await self.execute_retweet(quest['quest']['ctaUrl'])
                else:
                    logger.warning(f"account {self.idx} | {quest_name} not support now")
                    continue

                claimed = await self.claim_reward(quest_id, quest_name)
                if not claimed:
                    logger.error(f'account {self.idx} claim {quest_name} reward failed ❌')
            except Exception as e:
                logger.error(f"account {self.idx} do quest {quest_name} failed | {e}")


async def start_opensea(semaphore, idx, private_key, sol_key, proxy, twitter_token, discord_token):
    async with semaphore:
        ua = UserAgent(browsers='chrome', os='windows', platforms='pc').random
        opensea = Opensea(idx, private_key, sol_key, ua, proxy, twitter_token, discord_token)
        await asyncio.sleep(random.randint(RandomWait[0], RandomWait[1]))
        try:
            await opensea.execute_opensea_odyssey()

        except Exception as e:
            import traceback
            err_ids.append(opensea.idx)
            logger.error(f"account ({opensea.idx}) complete quest failed ❌：{e}{traceback.print_exc()}")


async def main(sync_num):
    accounts, sol_accounts, proxies, twitter_tokens, discord_tokens = read_files()

    semaphore = asyncio.Semaphore(sync_num)
    missions = []

    rerun_ids = []
    for rerun_id in RerunIds:
        if isinstance(rerun_id, int):
            rerun_ids.append(rerun_id)
        elif isinstance(rerun_id, tuple):
            for r_id in range(rerun_id[0], rerun_id[1] + 1):
                rerun_ids.append(r_id)
        else:
            return

    for idx in range(len(accounts)):
        if len(rerun_ids) != 0 and idx + 1 not in rerun_ids:
            continue
        private_key = accounts[idx]
        sol_key = sol_accounts[idx]
        proxy = proxies[idx]
        twitter_token = twitter_tokens[idx]
        discord_token = discord_tokens[idx]

        missions.append(
            asyncio.create_task(
                start_opensea(semaphore, idx + 1, private_key, sol_key, proxy, twitter_token, discord_token)))

    await asyncio.gather(*missions)


def read_files():
    xlsx_file = 'account_info.xlsx'
    df = pd.read_excel(xlsx_file, sheet_name='Sheet1')

    # 提取每列数据，去除空值和首尾空白
    accounts = df['evm_account'].dropna().str.strip().tolist()
    sol_accounts = df['solana_account'].dropna().str.strip().tolist()
    proxies = df['proxy'].dropna().str.strip().tolist()
    twitter_tokens = df['twitter_token'].dropna().str.strip().tolist()
    discord_tokens = df['discord_token'].dropna().str.strip().tolist()

    return accounts, sol_accounts, proxies, twitter_tokens, discord_tokens


if __name__ == '__main__':
    err_ids = []
    asyncio.run(main(SyncNum))
    print(err_ids)
