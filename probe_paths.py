import asyncio
import httpx
from aura.ui.formatter import console

async def test_endpoints():
    domains = [
        "https://indorse.io",
        "https://api.indorse.io",
        "https://app.indorse.io"
    ]
    paths = [
        "/admin/users",
        "/users/delete",
        "/profile/avatar",
        "/api/v1/admin/users",
        "/api/admin/users"
    ]
    
    console.print(f"[*] Probing extracted endpoints for unauthenticated access...")
    try:
         async with httpx.AsyncClient(verify=False, timeout=10) as client:
             for d in domains:
                 for p in paths:
                     url = d + p
                     try:
                         r = await client.get(url, follow_redirects=False)
                         if r.status_code == 200:
                             content_type = r.headers.get('content-type', '').lower()
                             if 'html' not in content_type:
                                 console.print(f"  [bold red][!!!] POTENTIAL LEAK: {url} -> {r.status_code} ({content_type})[/bold red]")
                                 console.print(f"    Preview: {r.text[:200]}")
                             else:
                                 console.print(f"  [yellow][.] HTML returned (likely Catch-all): {url}[/yellow]")
                         elif r.status_code in [401, 403]:
                             pass # Expected behavior
                         else:
                             console.print(f"  [.] {url} -> {r.status_code}")
                     except Exception as e:
                         pass
    except Exception as e:
         pass
         
if __name__ == "__main__":
    asyncio.run(test_endpoints())
