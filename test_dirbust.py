import asyncio
from aura.modules.scanner import AuraScanner

async def main():
    scanner = AuraScanner()
    # Mocking wordlist to test if check_dir explicitly hangs
    print("Testing DirBuster against zero.webappsecurity.com")
    paths = await scanner.dirbust("http://zero.webappsecurity.com")
    print("\nDONE!")
    print(paths)

if __name__ == "__main__":
    asyncio.run(main())
