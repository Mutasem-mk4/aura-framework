import asyncio
from playwright.async_api import async_playwright

async def run():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            viewport={'width': 1280, 'height': 800}
        )
        page = await context.new_page()
        
        print("[*] Navigating to coinhako.com...")
        try:
            # Go to home page
            await page.goto('https://www.coinhako.com', timeout=60000, wait_until="networkidle")
            
            # Save a screenshot to see what's happening
            screenshot_path = "coinhako_view.png"
            await page.screenshot(path=screenshot_path)
            print(f"[+] Screenshot saved to {screenshot_path}")
            
            # Get title and all script sources
            title = await page.title()
            print(f"[+] Page Title: {title}")
            
            scripts = await page.evaluate('() => Array.from(document.scripts).map(s => s.src)')
            print("[+] Found JS Bundles:")
            for s in scripts:
                if s:
                    print(s)
            
            # Check for turnstile or captcha
            content = await page.content()
            if "turnstile" in content.lower() or "captcha" in content.lower():
                print("[!] Turnstile/Captcha detected on page!")

        except Exception as e:
            print(f"[!] Error: {e}")
        finally:
            await browser.close()

if __name__ == "__main__":
    asyncio.run(run())
