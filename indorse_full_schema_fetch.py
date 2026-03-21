import asyncio
import httpx
import json
from aura.ui.formatter import console

async def fetch_full_schema():
    url = "https://api-prod-test.indorse.io/graphql"
    console.print(f"[*] Fetching Full Schema -> {url}")
    
    # Full Introspection Query
    query = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args { name type { name kind ofType { name kind } } }
            type { name kind ofType { name kind } }
          }
        }
      }
    }
    """
    
    async with httpx.AsyncClient(verify=False, timeout=20) as client:
        try:
            r = await client.post(url, json={"query": query})
            if r.status_code == 200:
                data = r.json()
                if "data" in data and "__schema" in data["data"]:
                    # Save to file
                    save_path = "indorse_prod_test_FULL_schema.json"
                    with open(save_path, "w") as f:
                        json.dump(data, f, indent=2)
                    console.print(f"  [bold green][+] Full Schema Saved to {save_path}[/bold green]")
                    
                    # Analyze for sensitive queries
                    queries = [q["name"] for q in data["data"]["__schema"]["types"] if q["name"] == "Query"][0]
                    # This is just a placeholder, we'll parse it properly in the next step
                    return True
            else:
                 console.print(f"  [.] GQL -> {r.status_code}")
        except Exception as e:
            console.print(f"  [red][!] Error: {e}[/red]")
    return False

if __name__ == "__main__":
    asyncio.run(fetch_full_schema())
