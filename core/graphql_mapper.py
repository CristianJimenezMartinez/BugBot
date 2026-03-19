import asyncio
import aiohttp
import logging
import json
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Optional
from core.config import Config

logger = logging.getLogger("BugBot.GraphQLMapper")

class GraphQLMapper:
    """
    Fase 11: Motor de Reconocimiento y Mapeo de GraphQL.
    100% Pasivo y Ético (Safe Harbor Compliance).
    Encuentra endpoints, saca la Introspection Query y disecciona la superficie de ataque (Queries/Mutations)
    para alimentar al analista o al AuthTester.
    """

    COMMON_ENDPOINTS = [
        "/graphql",
        "/api/graphql",
        "/v1/graphql",
        "/v2/graphql",
        "/graphql/v1",
        "/graphql/console",
        "/graph",
        "/graphql.php",
        "/gql",
        "/api/gql",
        "/graphql/api",
        "/query",
    ]

    # Mutations que indican funcionalidad sensible (escalable en bounties)
    DANGEROUS_MUTATIONS = [
        "delete", "remove", "destroy", "drop",
        "update", "modify", "edit", "patch",
        "create", "add", "insert", "register",
        "admin", "role", "permission", "privilege",
        "password", "reset", "token", "auth",
        "transfer", "payment", "charge", "refund",
        "upload", "import", "execute", "run",
    ]

    INTROSPECTION_QUERY = {
        "query": "\n    query IntrospectionQuery {\n      __schema {\n        queryType { name }\n        mutationType { name }\n        subscriptionType { name }\n        types {\n          ...FullType\n        }\n      }\n    }\n\n    fragment FullType on __Type {\n      kind\n      name\n      description\n      fields(includeDeprecated: true) {\n        name\n        description\n        args {\n          ...InputValue\n        }\n        type {\n          ...TypeRef\n        }\n        isDeprecated\n        deprecationReason\n      }\n      inputFields {\n        ...InputValue\n      }\n      interfaces {\n        ...TypeRef\n      }\n      enumValues(includeDeprecated: true) {\n        name\n        description\n        isDeprecated\n        deprecationReason\n      }\n      possibleTypes {\n        ...TypeRef\n      }\n    }\n\n    fragment InputValue on __InputValue {\n      name\n      description\n      type { ...TypeRef }\n      defaultValue\n    }\n\n    fragment TypeRef on __Type {\n      kind\n      name\n      ofType {\n        kind\n        name\n        ofType {\n          kind\n          name\n          ofType {\n            kind\n            name\n            ofType {\n              kind\n              name\n              ofType {\n                kind\n                name\n                ofType {\n                  kind\n                  name\n                  ofType {\n                    kind\n                    name\n                  }\n                }\n              }\n            }\n          }\n        }\n      }\n    }\n  "
    }

    def __init__(self, concurrency: int = 5):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.timeout = aiohttp.ClientTimeout(total=10)
        self.findings = []
        
    async def _check_endpoint(self, session: aiohttp.ClientSession, url: str) -> Optional[Dict]:
        """Envía la Introspection Query a un posible endpoint de GraphQL."""
        headers = Config.CUSTOM_HEADERS.copy()
        headers["User-Agent"] = Config.get_random_user_agent()
        headers["Content-Type"] = "application/json"
        headers["Accept"] = "application/json"
        
        async with self.semaphore:
            try:
                # Estructura del Payload profesional de GraphQL
                payload = {
                    "query": self.INTROSPECTION_QUERY["query"], 
                    "variables": {}, 
                    "operationName": "IntrospectionQuery"
                }

                # Usamos POST que es el estándar para GraphQL
                async with session.post(url, json=payload, headers=headers, timeout=self.timeout, allow_redirects=False) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data and "data" in data and "__schema" in data["data"]:
                            logger.error(f"\n[💎] ¡GRAPHQL INTROSPECTION EXPUESTA! {url}")
                            # Analizamos el esquema para facilitar la vida al hacker
                            schema_info = self._parse_schema(data["data"]["__schema"])
                            return {
                                "tipo": "GRAPHQL_INTROSPECTION",
                                "impacto": "MEDIUM", # Standard Bug Bounty Severity for pure introspection
                                "url": url,
                                "detalles": f"Introspección abierta. Queries: {schema_info['q_count']} | Mutations: {schema_info['m_count']}",
                                "schema_dump_size": len(json.dumps(data)),
                                "schema_summary": schema_info
                            }
            except Exception:
                pass
        return None

    def _parse_schema(self, schema: Dict) -> Dict:
        """Destripa el JSON gigante de GraphQL en una lista limpia de Queries y Mutations."""
        result = {
            "q_count": 0,
            "m_count": 0,
            "queries": [],
            "mutations": []
        }
        
        try:
            query_type_name = schema.get("queryType", {}).get("name", "Query") if schema.get("queryType") else "Query"
            mutation_type_name = schema.get("mutationType", {}).get("name", "Mutation") if schema.get("mutationType") else "Mutation"
            
            types = schema.get("types", [])
            for t in types:
                if t.get("name") == query_type_name:
                    fields = t.get("fields") or []
                    result["q_count"] = len(fields)
                    for f in fields:
                        args = [a.get("name") for a in f.get("args", [])]
                        result["queries"].append(f"{f.get('name')}({', '.join(args)})")
                        
                elif t.get("name") == mutation_type_name:
                    fields = t.get("fields") or []
                    result["m_count"] = len(fields)
                    for f in fields:
                        args = [a.get("name") for a in f.get("args", [])]
                        result["mutations"].append(f"{f.get('name')}({', '.join(args)})")
        except Exception as e:
            logger.debug(f"[GraphQL Parse Error] {e}")
            
        return result

    def _find_dangerous_mutations(self, mutations: list) -> list:
        """Identifica mutations sensibles que podrían ser explotables."""
        dangerous = []
        for m in mutations:
            m_lower = m.lower()
            for keyword in self.DANGEROUS_MUTATIONS:
                if keyword in m_lower:
                    dangerous.append(m)
                    break
        return dangerous

    async def run(self, base_url: str) -> List[Dict]:
        """Toma una URL base detectada (ej: api.playtika.com) e intenta cazar su GraphQL."""
        print(f"   [+] Thread GraphQL -> Buscando esquemas expuestos en {base_url}")
        
        # 1. Añadir la URL base original EXACTA por si el crawler ya la detectó
        test_urls = [base_url]
        
        # 2. Construir URLs comunes relativas al root_url (scheme + netloc)
        parsed = urlparse(base_url)
        root_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for p in self.COMMON_ENDPOINTS:
            test_urls.append(urljoin(root_url, p))
            
        # 3. Eliminar duplicados manteniendo el orden (base_url primero)
        test_urls = list(dict.fromkeys(test_urls))
        
        connector = Config.get_connector()
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self._check_endpoint(session, url) for url in test_urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
        for r in results:
            if r and not isinstance(r, Exception):
                # Analizar mutations peligrosas
                schema_info = r.get('schema_summary', {})
                dangerous = self._find_dangerous_mutations(schema_info.get('mutations', []))
                if dangerous:
                    r['impacto'] = 'HIGH'
                    r['dangerous_mutations'] = dangerous
                    r['detalles'] += f" | ⚠️ Mutations peligrosas: {len(dangerous)}"
                    r['curl_poc'] = f'curl -X POST -H "Content-Type: application/json" -d \'{{"query":"{{__schema{{mutationType{{name}}}}}}"}}\' "{r["url"]}"'
                
                self.findings.append(r)
                break
                
        return self.findings

# Test de Consola Independiente
if __name__ == "__main__":
    import sys
    async def test():
        target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
        mapper = GraphQLMapper()
        print(f"[*] Escaneando GraphQL en {target}")
        res = await mapper.run(target)
        if res:
            print("\n¡Resultados!")
            print(json.dumps(res, indent=2))
        else:
            print("Nada encontrado.")
    asyncio.run(test())
