from settings import NOCAPTCHA_API_KEY
from curl_cffi.requests import AsyncSession


class NoCaptcha:
    def __init__(self):
        self.headers = {
            'User-Token': NOCAPTCHA_API_KEY,
            'Content-Type': 'application/json',
        }
        self.sess = AsyncSession(headers=self.headers)

    async def solve_cloudflare(self, site_url, proxy, captcha_data: dict = None):
        json_data = {
            'href': site_url,
            'proxy': proxy,
        }
        if captcha_data:
            json_data.update(captcha_data)

        response = await self.sess.post('http://api.nocaptcha.io/api/wanda/cloudflare/universal', json=json_data)
        resp = response.json()
        if resp['status'] != 1:
            raise Exception(f'获取captcha结果失败: {resp["msg"]}')

        return resp
