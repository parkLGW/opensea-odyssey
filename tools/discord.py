import base64
import json
from curl_cffi.requests import AsyncSession, BrowserType
from tools.twitter import get_query_param

class Discord:
    def __init__(self, idx, discord_token, user_agent, proxy):
        self.idx = idx
        self.headers = {
            'authority': 'discord.com',
            'accept': '*/*',
            'accept-language': 'zh-CN,zh;q=0.9',
            'authorization': discord_token,
            'content-type': 'application/json',
            'origin': 'https://discord.com',
            'priority': 'u=1, i',
            'sec-ch-ua': '"Chromium";v="132", "Google Chrome";v="132", "Not-A.Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': user_agent,
            'x-debug-options': 'bugReporterEnabled',
            'x-discord-locale': 'zh-CN',
            'x-discord-timezone': 'Asia/Hong_Kong',
            'x-super-properties': self.get_x_properties(user_agent),
        }
        self.proxies = {
            "http": f"socks5://{proxy}",
            "https": f"socks5://{proxy}"
        }
        self.sess = AsyncSession(
            proxies=self.proxies,
            impersonate=BrowserType.chrome120
        )

    def get_x_properties(self, user_agent):
        data = {
            "os": "Windows",
            "browser": "Chrome",
            "device": "",
            "system_locale": "zh-HK",
            "browser_user_agent": user_agent,
            "browser_version": "124.0.0.0",
            "os_version": "10",
            "referrer": "",
            "referring_domain": "",
            "referrer_current": "",
            "referring_domain_current": "",
            "release_channel": "stable",
            "client_build_number": 355624,
            "client_event_source": None,
            "has_client_mods": None
        }
        return base64.b64encode(json.dumps(data).encode()).decode('utf-8')

    async def get_user_info(self):
        headers = self.headers.copy()
        headers.update({
            'Referer': 'https://discord.com/channels/@me'
        })
        headers.pop('content-type')

        response = await self.sess.get('https://discord.com/api/v9/users/@me', headers=headers)
        if response.status_code != 200:
            raise Exception(f"account ({self.idx}) get user info failed ❌")

        res = json.loads(response.text)
        return res

    async def authorize(self, params, json_data):
        headers = self.headers.copy()

        response = await self.sess.post(
            'https://discord.com/api/v9/oauth2/authorize',
            params=params,
            headers=headers,
            json=json_data,
        )

        if response.status_code != 200:
            if "Unauthorized" in response.text:
                raise Exception(f"account {self.idx} | Check your discord token, it might be locked.")
            raise Exception(f"account ({self.idx}) fetch discord oauth data failed ❌")

        res = response.json()
        code = get_query_param(res['location'], 'code')

        return code
