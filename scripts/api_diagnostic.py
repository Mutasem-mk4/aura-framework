import asyncio
import os
from dotenv import load_dotenv
from curl_cffi import requests
from rich.console import Console
from rich.table import Table

console = Console()
load_dotenv()

async def test_api(name, url, method="GET", headers=None, auth=None, params=None, json_data=None):
    console.print(f"[bold cyan]Testing {name}...[/bold cyan]")
    try:
        resp = await asyncio.to_thread(
            requests.request, 
            method,
            url, 
            headers=headers, 
            auth=auth, 
            params=params, 
            json=json_data,
            timeout=15,
            verify=False
        )
        if resp.status_code == 200:
            console.print(f"[bold green][PASS] {name} Success! (200 OK)[/bold green]")
            return "SUCCESS", resp.status_code
        elif resp.status_code == 401:
            console.print(f"[bold red][FAIL] {name} Authentication Error (401): Check ID/Secret[/bold red]")
            try:
                console.print(f"[dim]Body: {resp.text[:100]}[/dim]")
            except: pass
            return "AUTH_ERROR", resp.status_code
        elif resp.status_code == 403:
            console.print(f"[bold red][FAIL] {name} Forbidden (403): Key valid but access denied or limited[/bold red]")
            try:
                # BinaryEdge often sends details in JSON
                console.print(f"[dim]Body: {resp.text[:100]}[/dim]")
            except: pass
            return "FORBIDDEN", resp.status_code
        else:
            console.print(f"[bold yellow][!] {name} Returned: {resp.status_code}[/bold yellow]")
            return "OTHER_ERROR", resp.status_code
    except Exception as e:
        console.print(f"[bold red][FAIL] {name} Connection Error: {e}[/bold red]")
        return "CONN_ERROR", str(e)

async def main():
    console.print("[bold magenta]Aura v15.1 API Diagnostic Tool[/bold magenta]\n")
    
    results = []
    
    # 1. Shodan
    shodan_key = os.getenv("SHODAN_API_KEY")
    if shodan_key:
        results.append(("Shodan", *await test_api("Shodan", f"https://api.shodan.io/api-info?key={shodan_key}")))
    else:
        results.append(("Shodan", "MISSING_KEY", "N/A"))

    # 2. VirusTotal
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    if vt_key:
        results.append(("VirusTotal", *await test_api("VirusTotal", "https://www.virustotal.com/api/v3/users/me", headers={"x-apikey": vt_key})))
    else:
        results.append(("VirusTotal", "MISSING_KEY", "N/A"))

    # 3. AlienVault OTX
    otx_key = os.getenv("OTX_API_KEY")
    if otx_key:
        results.append(("AlienVault", *await test_api("AlienVault", "https://otx.alienvault.com/api/v1/pulses/subscribed", headers={"X-OTX-API-KEY": otx_key})))
    else:
        results.append(("AlienVault", "MISSING_KEY", "N/A"))

    # 4. AbuseIPDB
    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    if abuse_key:
        results.append(("AbuseIPDB", *await test_api("AbuseIPDB", "https://api.abuseipdb.com/api/v2/check", headers={"Key": abuse_key}, params={"ipAddress": "8.8.8.8"})))
    else:
        results.append(("AbuseIPDB", "MISSING_KEY", "N/A"))

    # 5. Censys
    c_id = os.getenv("CENSYS_API_ID")
    c_secret = os.getenv("CENSYS_API_SECRET")
    if c_id and c_secret:
        import base64
        # Try without "censys_" prefix if present
        clean_secret = c_secret.replace("censys_", "")
        auth_str = base64.b64encode(f"{c_id}:{clean_secret}".encode()).decode()
        headers = {"Authorization": f"Basic {auth_str}", "User-Agent": "Aura/16.1"}
        results.append(("Censys (Clean)", *await test_api("Censys (Clean)", "https://search.censys.io/api/v2/hosts/8.8.8.8", headers=headers)))
    else:
        results.append(("Censys", "MISSING_KEY", "N/A"))

    # 6. GreyNoise
    gn_key = os.getenv("GREYNOISE_API_KEY")
    if gn_key:
        results.append(("GreyNoise", *await test_api("GreyNoise", "https://api.greynoise.io/v3/community/8.8.8.8", headers={"key": gn_key})))
    else:
        results.append(("GreyNoise", "MISSING_KEY", "N/A"))

    # 7. SecurityTrails
    st_key = os.getenv("SECURITYTRAILS_API_KEY")
    if st_key:
        results.append(("SecurityTrails", *await test_api("SecurityTrails", "https://api.securitytrails.com/v1/ping", headers={"apikey": st_key})))
    else:
        results.append(("SecurityTrails", "MISSING_KEY", "N/A"))

    # 8. BinaryEdge
    be_key = os.getenv("BINARYEDGE_API_KEY")
    if be_key:
        headers = {
            "X-Key": be_key,
            "User-Agent": "Aura Intelligence OSINT/16.1"
        }
        results.append(("BinaryEdge", *await test_api("BinaryEdge", "https://api.binaryedge.io/v2/query/search/stats?query=type:vulnerability", headers=headers)))
    else:
        results.append(("BinaryEdge", "MISSING_KEY", "N/A"))

    # 9. IntelX
    ix_key = os.getenv("INTELX_API_KEY")
    if ix_key:
        # Use POST for IntelX
        results.append(("IntelX", *await test_api("IntelX", "https://2.intelx.io/phonebook/search", method="POST", headers={"x-key": ix_key}, json_data={"term": "example.com", "maxresults": 1})))
    else:
        results.append(("IntelX", "MISSING_KEY", "N/A"))

    # 10. IntelX (Alt) - Trying the UUID given as Censys ID
    alt_ix_key = os.getenv("CENSYS_API_ID")
    if alt_ix_key:
        results.append(("IntelX (Alt)", *await test_api("IntelX (Alt)", "https://2.intelx.io/phonebook/search", method="POST", headers={"x-key": alt_ix_key}, json_data={"term": "example.com", "maxresults": 1})))

    # 11. FullHunt
    fh_key = os.getenv("FULLHUNT_API_KEY")
    if fh_key:
        results.append(("FullHunt", *await test_api("FullHunt", "https://fullhunt.io/api/v1/auth/status", headers={"X-API-KEY": fh_key})))
    else:
        results.append(("FullHunt", "MISSING_KEY", "N/A"))
        
    # 12. Cross-Check JS0S Key against alternatives
    test_key = os.getenv("FULLHUNT_API_KEY") # JS0S...
    if test_key:
         results.append(("JS0S-on-Hunter", *await test_api("JS0S-on-Hunter", f"https://api.hunter.io/v2/account?api_key={test_key}")))
         results.append(("JS0S-on-Netlas", *await test_api("JS0S-on-Netlas", "https://app.netlas.io/api/users/current", headers={"X-API-Key": test_key})))
         results.append(("JS0S-on-ZoomEye", *await test_api("JS0S-on-ZoomEye", "https://api.zoomeye.org/resources/info", headers={"API-KEY": test_key})))

    # 13. Cross-Check UUID Key against alternatives
    uuid_key = os.getenv("INTELX_API_KEY") # C977...
    if uuid_key:
         results.append(("UUID-on-ZoomEye", *await test_api("UUID-on-ZoomEye", "https://api.zoomeye.org/resources/info", headers={"API-KEY": uuid_key})))

    # Display Table
    table = Table(title="Diagnostic Summary")
    table.add_column("Service", style="cyan")
    table.add_column("Status", style="magenta")
    table.add_column("Details", style="green")

    for res in results:
        color = "green" if res[1] == "SUCCESS" else "red" if "ERROR" in res[1] else "yellow"
        table.add_row(res[0], f"[{color}]{res[1]}[/{color}]", str(res[2]))

    console.print("\n", table)

if __name__ == "__main__":
    asyncio.run(main())
