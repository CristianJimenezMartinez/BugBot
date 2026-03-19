import asyncio
import aiohttp
import uuid
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

async def test_register():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pem_str = pem.decode("utf-8").replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replace("\n", "")
    
    correlation_id = str(uuid.uuid4())[:13]
    session_id = str(uuid.uuid4())
    
    payload = {
        "public-key": pem_str,
        "secret-key": session_id,
        "correlation-id": correlation_id
    }
    
    headers = {"Content-Type": "application/json"}
    
    server = "https://oast.fun"
    try:
        resolver = aiohttp.ThreadedResolver()
        connector = aiohttp.TCPConnector(resolver=resolver, use_dns_cache=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.post(f"{server}/register", json=payload, headers=headers, timeout=10) as resp:
                print(f"Status: {resp.status}")
                text = await resp.text()
                print(f"Response: {text}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_register())
