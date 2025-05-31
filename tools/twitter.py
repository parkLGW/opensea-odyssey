import random
import json
import base64
import binascii
import aiohttp
from aiohttp import ClientResponse
import asyncio
from aiohttp_socks import ProxyConnector
from curl_cffi.requests import AsyncSession, BrowserType
from urllib.parse import urlparse, parse_qs

MAX_TRIES = 3
DISABLE_SSL = False


def get_query_param(url: str, name: str):
    values = parse_qs(urlparse(url).query).get(name)
    if values:
        return values[0]
    return None


def generate_csrf_token(size=16):
    data = random.getrandbits(size * 8).to_bytes(size, "big")
    return binascii.hexlify(data).decode()


def get_conn(proxy):
    return ProxyConnector.from_url(proxy) if proxy else None


def base64_encode(string):
    string = string.encode() if isinstance(string, str) else string
    return base64.b64encode(string).decode()


async def handle_aio_response(resp_raw: ClientResponse, acceptable_statuses=None, resp_handler=None, with_text=False):
    if acceptable_statuses and len(acceptable_statuses) > 0:
        if resp_raw.status not in acceptable_statuses:
            raise Exception(f'Bad status code [{resp_raw.status}]: Response = {await resp_raw.text()}')
    try:
        if resp_handler is not None:
            if with_text:
                return resp_handler(await resp_raw.text())
            else:
                return resp_handler(await resp_raw.json())
        return
    except Exception as e:
        raise Exception(f'{str(e)}: Status = {resp_raw.status}. Response = {await resp_raw.text()}')


def async_retry(async_func):
    async def wrapper(*args, **kwargs):
        tries, delay = MAX_TRIES, 1.5
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


def _get_headers(user_agent) -> dict:
    return {
        'accept': '*/*',
        'accept-language': 'zh-HK,zh-TW;q=0.9,zh;q=0.8',
        'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA',
        'content-type': 'application/json',
        'origin': 'https://x.com',
        'referer': 'https://x.com/',
        'sec-ch-ua': '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"macOS"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'x-twitter-active-user': 'yes',
        'x-twitter-auth-type': 'OAuth2Session',
        'x-twitter-client-language': 'zh-cn',
        'x-csrf-token': '',
        'user-agent': user_agent,
    }


class Twitter:
    def __init__(self, twitter_token, proxy, user_agent, ct0=''):
        self.cookies = {
            'auth_token': twitter_token
        }
        self.ct0 = ct0
        self.headers = _get_headers(user_agent)
        self.my_user_id = None
        self.my_username = None
        self.language = 'zh-cn'
        if proxy:
            proxy_str = proxy if proxy.startswith('http://') else f'socks5://{proxy}'
            self.proxy = proxy_str
            self.proxies = {
                "http": proxy_str,
                "https": proxy_str
            }
            self.sess = AsyncSession(
                proxies=self.proxies,
                impersonate=BrowserType.chrome124
            )
        else:
            self.sess = AsyncSession(impersonate=BrowserType.chrome124)
            self.proxy = None
        self.user_agent = user_agent

    async def start(self):
        ct0 = await self._get_ct0()
        self.cookies.update({'ct0': ct0})
        self.headers.update({'x-csrf-token': ct0})

        self.my_username = await self.get_my_profile_info()
        self.my_user_id = await self.get_user_id(self.my_username)

    def set_cookies(self, resp_cookies):
        self.cookies.update({name: value.value for name, value in resp_cookies.items()})

    @async_retry
    async def request(self, method, url, acceptable_statuses=None, resp_handler=None, with_text=False, **kwargs):
        headers = self.headers.copy()
        cookies = self.cookies.copy()

        if 'headers' in kwargs:
            headers.update(kwargs.pop('headers'))
        if 'cookies' in kwargs:
            cookies.update(kwargs.pop('cookies'))
        try:
            async with aiohttp.ClientSession(connector=get_conn(self.proxy), headers=headers, cookies=cookies) as sess:
                if method.lower() == 'get':
                    async with sess.get(url, **kwargs) as resp:
                        self.set_cookies(resp.cookies)
                        return await handle_aio_response(resp, acceptable_statuses, resp_handler, with_text)
                elif method.lower() == 'post':
                    async with sess.post(url, **kwargs) as resp:
                        self.set_cookies(resp.cookies)
                        return await handle_aio_response(resp, acceptable_statuses, resp_handler, with_text)
                else:
                    raise Exception('Wrong request method')
        except Exception as e:
            self.twitter_error = True
            raise e

    async def _get_ct0(self):
        try:
            kwargs = {'ssl': False} if DISABLE_SSL else {}
            async with aiohttp.ClientSession(connector=get_conn(self.proxy),
                                             headers=self.headers, cookies=self.cookies) as sess:
                params = {
                    'variables': '{"withCommunitiesMemberships":true}',
                    'features': '{"rweb_tipjar_consumption_enabled":true,"responsive_web_graphql_exclude_directive_enabled":true,"verified_phone_label_enabled":false,"creator_subscriptions_tweet_preview_api_enabled":true,"responsive_web_graphql_skip_user_profile_image_extensions_enabled":false,"responsive_web_graphql_timeline_navigation_enabled":true}',
                    'fieldToggles': '{"isDelegate":false,"withAuxiliaryUserLabels":false}',
                }
                kwargs['params'] = params
                async with sess.get('https://api.x.com/graphql/HC-1ZetsBT1HKVUOvnLE8Q/Viewer', **kwargs) as resp:
                    new_csrf = resp.cookies.get("ct0")
                    if new_csrf is None:
                        raise Exception('Empty new csrf')
                    new_csrf = new_csrf.value
                    return new_csrf
        except Exception as e:
            reason = 'Your account has been locked\n' if 'Your account has been locked' in str(e) else ''
            self.twitter_error = True
            raise Exception(f'Failed to get ct0 for twitter: {reason}{str(e)}')

    async def get_my_profile_info(self):
        url = 'https://api.x.com/1.1/account/settings.json'
        params = {
            'include_mention_filter': 'true',
            'include_nsfw_user_flag': 'true',
            'include_nsfw_admin_flag': 'true',
            'include_ranked_timeline': 'true',
            'include_alt_text_compose': 'true',
            'ext': 'ssoConnections',
            'include_country_code': 'true',
            'include_ext_dm_nsfw_media_filter': 'true',
            'include_ext_sharing_audiospaces_listening_data_with_followers': 'true',
        }
        try:
            return await self.request("GET", url, params=params, resp_handler=lambda r: r['screen_name'].lower())
        except Exception as e:
            raise Exception(f'Get my username error: {str(e)}')

    async def get_user_id(self, username):
        url = 'https://x.com/i/api/graphql/-0XdHI-mrHWBQd8-oLo1aA/ProfileSpotlightsQuery'
        if username[0] == '@':
            username = username[1:]
        username = username.lower()
        params = {
            'variables': to_json({'screen_name': username})
        }
        try:
            return await self.request(
                "GET", url, params=params,
                resp_handler=lambda r: int(r['data']['user_result_by_screen_name']['result']['rest_id'])
            )
        except Exception as e:
            raise Exception(f'Get user id error: {str(e)}')

    async def follow(self, username):
        user_id = await self.get_user_id(username)
        url = 'https://api.x.com/1.1/friendships/create.json'
        params = {
            'include_profile_interstitial_type': '1',
            'include_blocking': '1',
            'include_blocked_by': '1',
            'include_followed_by': '1',
            'include_want_retweets': '1',
            'include_mute_edge': '1',
            'include_can_dm': '1',
            'include_can_media_tag': '1',
            'include_ext_has_nft_avatar': '1',
            'include_ext_is_blue_verified': '1',
            'include_ext_verified_type': '1',
            'include_ext_profile_image_shape': '1',
            'skip_status': '1',
            'user_id': user_id,
        }
        headers = {
            'content-type': 'application/x-www-form-urlencoded'
        }
        try:
            await self.request('POST', url, params=params, headers=headers, resp_handler=lambda r: r['id'])
        except Exception as e:
            raise Exception(f'Follow error: {str(e)}')

    async def post_tweet(self, text, tweet_id=None) -> str:
        action = "CreateTweet"
        query_id = "YgQ5N_ceVFtTazfQcUlmvg"
        _json = dict(
            variables=dict(
                tweet_text=text,
                media=dict(
                    media_entities=[],
                    possibly_sensitive=False
                ),
                semantic_annotation_ids=[],
                dark_request=False,
                disallowed_reply_options=None,
            ),
            features=dict(
                freedom_of_speech_not_reach_fetch_enabled=True,
                graphql_is_translatable_rweb_tweet_is_translatable_enabled=True,
                longform_notetweets_consumption_enabled=True,
                longform_notetweets_inline_media_enabled=True,
                longform_notetweets_rich_text_read_enabled=True,
                responsive_web_edit_tweet_api_enabled=True,
                responsive_web_enhance_cards_enabled=False,
                responsive_web_graphql_exclude_directive_enabled=True,
                responsive_web_graphql_skip_user_profile_image_extensions_enabled=False,
                responsive_web_graphql_timeline_navigation_enabled=True,
                standardized_nudges_misinfo=True,
                tweet_awards_web_tipping_enabled=False,
                tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled=True,
                verified_phone_label_enabled=False,
                view_counts_everywhere_api_enabled=True,
                articles_preview_enabled=True,
                rweb_tipjar_consumption_enabled=True,
                profile_label_improvements_pcf_label_in_post_enabled=False,
                creator_subscriptions_quote_tweet_preview_enabled=False,
                responsive_web_twitter_article_tweet_consumption_enabled=True,
                responsive_web_grok_analyze_post_followups_enabled=False,
                responsive_web_grok_analyze_button_fetch_trends_enabled=False,
                c9s_tweet_anatomy_moderator_badge_enabled=True,
                communities_web_enable_tweet_community_results_fetch=True,
                premium_content_api_read_enabled=False,
                responsive_web_grok_analysis_button_from_backend=False,
                responsive_web_grok_image_annotation_enabled=True,
                responsive_web_grok_share_attachment_enabled=True,
                responsive_web_jetfuel_frame=False

            ),
            queryId=query_id)

        if tweet_id:
            _json['variables']['reply'] = dict(
                in_reply_to_tweet_id=tweet_id,
                exclude_reply_user_ids=[]
            )

        url = f'https://x.com/i/api/graphql/{query_id}/{action}'

        def _handler(resp):
            _result = resp['data']['create_tweet']['tweet_results']['result']
            _username = _result['core']['user_results']['result']['legacy']['screen_name']
            _tweet_id = _result['rest_id']
            _url = f'https://x.com/{_username}/status/{_tweet_id}'
            return _url

        try:
            return await self.request('POST', url, json=_json, resp_handler=_handler)
        except Exception as e:
            raise Exception(f'Post tweet error: {str(e)}')

    async def retweet(self, tweet_id):
        action = 'CreateRetweet'
        query_id = 'ojPdsZsimiJrUGLR1sjUtA'
        url = f'https://x.com/i/api/graphql/{query_id}/{action}'
        _json = {
            'variables': {
                'tweet_id': tweet_id,
                'dark_request': False
            },
            'queryId': query_id
        }
        try:
            return await self.request('POST', url, json=_json, resp_handler=lambda r: r)
        except Exception as e:
            raise Exception(f'Retweet error: {str(e)}')

    async def like(self, tweet_id) -> bool:
        action = 'FavoriteTweet'
        query_id = 'lI07N6Otwv1PhnEgXILM7A'
        url = f'https://x.com/i/api/graphql/{query_id}/{action}'
        _json = {
            'variables': {
                'tweet_id': tweet_id,
                'dark_request': False
            },
            'queryId': query_id
        }
        try:
            return await self.request(
                'POST', url, json=_json,
                resp_handler=lambda r: r['data']['favorite_tweet'] == 'Done'
            )
        except Exception as e:
            raise Exception(f'Like error: {str(e)}')

    async def oauth_v2(self, response_type, client_id, redirect_uri, scope, state, code_challenge,
                       code_challenge_method):

        cookies = self.cookies.copy()
        headers = self.headers.copy()
        headers.update({
            'authority': 'x.com'
        })

        params = {
            'response_type': response_type,
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'scope': scope,
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': code_challenge_method,
        }

        auth_code = await self.request('GET', 'https://x.com/i/api/2/oauth2/authorize', params=params,
                                       cookies=cookies, headers=headers, resp_handler=lambda r: r['auth_code'])

        headers.pop('authority')
        headers.update({'content-type': 'application/x-www-form-urlencoded'})

        data = {
            'approval': 'true',
            'code': auth_code,
        }

        redirect_uri = await self.request('POST', 'https://x.com/i/api/2/oauth2/authorize', cookies=cookies,
                                          headers=headers, data=data, resp_handler=lambda r: r['redirect_uri'])

        return auth_code, redirect_uri


def to_json(obj):
    return json.dumps(obj, separators=(',', ':'), ensure_ascii=True)
