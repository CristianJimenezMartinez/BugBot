import os
import sys
import json
import urllib.request
import urllib.parse
import ssl

def main():
    print(r"""
==================================================
  📦 SOURCEMAP UNPACKER (BugBot v3.5 Tools) 📦
==================================================
""")

    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = input("[?] Introduce la URL del archivo .map (ej. https://web.com/app.js.map): ").strip()

    if not url:
        print("[-] URL vacía. Saliendo.")
        sys.exit(1)

    # Ignorar errores SSL al descargar
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    parsed_url = urllib.parse.urlparse(url)
    domain = parsed_url.netloc.replace('.', '_')
    filename = os.path.basename(parsed_url.path) or "unknown.map"
    
    # Determinar ruta del proyecto
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.dirname(script_dir)  # Raiz de BugBot -> D:\Python\Bug Bounty
    
    # Enrutar a la carpeta targets/DOMINIO/source_code...
    target_dir = os.path.join(base_dir, "targets", domain)
    output_dir = os.path.join(target_dir, f"source_code_{filename.replace('.map', '')}")
    
    os.makedirs(target_dir, exist_ok=True)
    
    print(f"\n[*] Descargando sourcemap en memoria desde: \n    {url}")
    print(f"[*] Destino programado: \n    {output_dir}\n")
    
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
        with urllib.request.urlopen(req, context=ctx) as response:
            data = json.loads(response.read().decode('utf-8'))
            
        sources = data.get('sources', [])
        contents = data.get('sourcesContent', [])
        
        if not contents:
            print("[-] Error: El archivo no contiene el código fuente ('sourcesContent' está vacío).")
            print("[!] Aviso: Esto suele pasar cuando el servidor sirve el map pero sin el código para engañar a los crawlers.")
            sys.exit(1)

        os.makedirs(output_dir, exist_ok=True)
        files_extracted = 0
        
        for i, filepath in enumerate(sources):
            # Limpiamos rutas sucias de Webpack, Angular, etc.
            clean_path = filepath.replace("webpack:///", "").replace("webpack://", "")\
                                 .replace("ng:///", "").replace("../", "").split("?")[0]
            
            clean_path = os.path.normpath(clean_path)
            
            # Impedir saltos de directorio (Seguridad LFI local)
            if clean_path.startswith(os.pardir) or os.path.isabs(clean_path):
                clean_path = os.path.basename(clean_path)
                
            full_path = os.path.join(output_dir, clean_path)
            
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            
            content = contents[i] if i < len(contents) else ""
            if content:
                with open(full_path, 'w', encoding='utf-8') as out_file:
                    out_file.write(content)
                files_extracted += 1
                
        print(f"[+] ¡Éxito! Se extrajeron {files_extracted} archivos de código fuente original.")
        print(f"[+] Abriendo la carpeta destino para que inspecciones...")
        
        if sys.platform == 'win32':
            os.startfile(output_dir)

    except Exception as e:
        print(f"\n[-] Ocurrió un error crítico de red o de parseo: {e}")

if __name__ == "__main__":
    main()
