import asyncio
import httpx
import json

async def introspect():
    url = "https://presto.indorse.io/graphql"
    query = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          kind
          name
          description
          fields(includeDeprecated: true) { name }
        }
      }
    }
    """
    
    try:
         async with httpx.AsyncClient(verify=False, timeout=10) as client:
             r = await client.post(url, json={"query": query})
             if r.status_code == 200:
                  print("Found Introspection Schema!")
                  data = r.json()
                  # save to file
                  with open("schema.json", "w") as f:
                       json.dump(data, f, indent=2)
                  print("Schema saved to schema.json")
             else:
                  print(f"Failed to fetch schema: {r.status_code}")
                  print(r.text[:500])
    except Exception as e:
         print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(introspect())
