import asyncio
from curl_cffi.requests import AsyncSession

async def main():
    s = AsyncSession()
    r = await s.get('https://dvwa.co.uk', impersonate='chrome110')
    print('Header Server:', r.headers.get('server'))
    print('Header Server lower:', r.headers.get('server', '').lower())

asyncio.run(main())
