import os
import zipfile
import tarfile
import logging
import shutil
from typing import List

logger = logging.getLogger("BugBot.Analyzer.Unpacker")

class FileUnpacker:
    """Motor atómico para descompresión segura y lectura de texto."""
    
    def __init__(self, unpacked_base_dir: str):
        self.unpacked_base_dir = unpacked_base_dir

    def unpack(self, filepath: str) -> str:
        """Desempaqueta archivos comprimidos y devuelve la ruta de extracción."""
        filename = os.path.basename(filepath)
        extract_dir = os.path.join(self.unpacked_base_dir, filename + '_extracted')
        
        try:
            if filepath.endswith('.zip') and zipfile.is_zipfile(filepath):
                with zipfile.ZipFile(filepath, 'r') as z:
                    z.extractall(extract_dir)
                return extract_dir
            elif filepath.endswith(('.tar', '.tar.gz', '.tgz')) and tarfile.is_tarfile(filepath):
                with tarfile.open(filepath, 'r:*') as t:
                    t.extractall(extract_dir)
                return extract_dir
        except Exception as e:
            logger.error(f"[-] Error desempaquetando {filepath}: {e}")
        return ""

    def read_text(self, path_or_dir: str, max_bytes: int = 5 * 1024 * 1024) -> str:
        """Lee el contenido de un archivo o directorio de forma segura."""
        if os.path.isfile(path_or_dir):
            try:
                with open(path_or_dir, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read(max_bytes)
            except: return ""
            
        content = ""
        total_read = 0
        valid_exts = {'.txt', '.env', '.json', '.js', '.php', '.config', '.sql', '.yml', '.yaml', '.xml', '.csv'}
        
        for root, _, files in os.walk(path_or_dir):
            for file in files:
                if total_read >= max_bytes: break
                if os.path.splitext(file)[1].lower() in valid_exts:
                    try:
                        with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                            chunk = f.read(max_bytes - total_read)
                            content += chunk + " "
                            total_read += len(chunk)
                    except: pass
        return content

    def cleanup(self, path: str):
        """Borra directorios temporales."""
        if os.path.isdir(path) and '_extracted' in path:
            try: shutil.rmtree(path)
            except: pass
