import requests
import time
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
import difflib

init(autoreset=True)

# Select a few representative endpoints from the findings
TARGETS = [
    {
        "url": "https://news.playtika.com/press-releases",
        "params": ["debug", "test", "dev", "admin", "config", "show", "internal", "auth", "secret", "env"]
    }
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
}

import re
import json

def extract_next_data(html_content):
    """Extrae el JSON de Next.js de forma ultra-rápida (sin BS4)"""
    match = re.search(r'<script id="__NEXT_DATA__" type="application/json">(.*?)</script>', html_content, re.DOTALL)
    if match:
        return match.group(1)
    return ""

def get_json_diff(base_json_str, test_json_str):
    try:
        base_obj = json.loads(base_json_str)
        test_obj = json.loads(test_json_str)
        
        # Encuentra las diferencias principales a nivel de clave en 'props' o 'pageProps' que suelen ser donde se inyecta la data
        diffs = []
        def compare_dicts(d1, d2, path=""):
            for k in d2:
                if k not in d1:
                    diffs.append(f"AÑADIDO: {path}[{k}] = {str(d2[k])[:100]}...")
                elif isinstance(d2[k], dict) and isinstance(d1.get(k), dict):
                    compare_dicts(d1[k], d2[k], path + f"[{k}]")
                elif d1.get(k) != d2[k]:
                    # diffs.append(f"MODIFICADO: {path}[{k}]") # Ignoramos modificados porque los timestamps cambian
                    pass
        
        compare_dicts(base_obj, test_obj)
        return diffs
    except:
        return ["Error parseando JSON de Next.js"]

def test_hidden_params():
    print(f"{Fore.CYAN}[*] Iniciando Análisis de Parámetros Ocultos (Versión Rápida) en Playtika.com")
    
    for target in TARGETS:
        base_url = target["url"]
        print(f"\n{Fore.YELLOW}[>] Analizando Endpoint: {base_url}")
        
        # 1. Obtener Baseline (Sin Parámetros)
        try:
            resp_base = requests.get(base_url, headers=HEADERS, timeout=10)
            base_next = extract_next_data(resp_base.text)
            base_len = len(resp_base.text)
            print(f"    {Fore.WHITE}[+] Baseline Obtenido - Status: {resp_base.status_code} | Longitud Raw: {base_len} bytes")
        except Exception as e:
             print(f"    {Fore.RED}[-] Error obteniendo Baseline: {e}")
             continue


             
        time.sleep(1) # Rate limit
        
        # 2. Inyectar Parámetros y Comparar
        for param in target["params"]:
            test_url = f"{base_url}?{param}=1"
            try:
                resp_test = requests.get(test_url, headers=HEADERS, timeout=10)
                test_next = extract_next_data(resp_test.text)
                test_len = len(resp_test.text)
                
                # Calcular la diferencia real basada en longitud
                diff_bytes = test_len - base_len
                
                # Calcular si el state de Next.js cambió (comparando strings en bruto en lugar de todo el HTML)
                if test_next and base_next and test_next != base_next:
                    print(f"    {Fore.GREEN}[!] Anomalía Detectada con: ?{param}=1")
                    print(f"        {Fore.GREEN}--> Diferencia Raw: {diff_bytes:+} bytes")
                    
                    # Vamos a aislar las diferencias JSON
                    diffs = get_json_diff(base_next, test_next)
                    if diffs:
                         print(f"        {Fore.RED}[!!!] El estado interno (__NEXT_DATA__) revela las siguientes claves inyectadas:")
                         for d in diffs[:10]: # Muestra los primeros 10
                             print(f"             {Fore.LIGHTRED_EX}{d}")
                         if len(diffs) > 10: print(f"             {Fore.LIGHTRED_EX}... y {len(diffs)-10} más.")
                    else:
                         print(f"        {Fore.YELLOW}[*] El JSON cambió pero parecen variaciones dinámicas (Timestamps/IDs).")
                         
                else:
                    if abs(diff_bytes) > 1000:
                         print(f"    {Fore.GREEN}[!] Anomalía de Tamaño con: ?{param}=1 ({diff_bytes:+} bytes), pero el state NEXT no varió visualmente.")
                    else:
                         print(f"    {Fore.LIGHTBLACK_EX}[-] Parámetro ?{param}=1 no produce cambios significativos en el JSON Interno.")
                    
            except Exception as e:
                print(f"    {Fore.RED}[-] Error con {param}=1: {e}")
            
            time.sleep(1)

if __name__ == "__main__":
    test_hidden_params()
