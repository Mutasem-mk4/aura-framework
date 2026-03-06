import asyncio
from curl_cffi.requests import AsyncSession

async def main():
    s = AsyncSession()
    r = await s.get('https://dvwa.co.uk', impersonate='chrome110')
    print('Status:', r.status_code)
    print('Server:', dict(r.headers).get('server', ''))

asyncio.run(main())
