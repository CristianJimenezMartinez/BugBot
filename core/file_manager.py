import os
import logging

class FileManager:
    """
    Gestor de Archivos Blindado (v1.1)
    - Maneja la persistencia física forzada en Windows.
    - Evita colisiones de directorios (WinError 183 Bypass).
    - Centraliza la sanitización de rutas.
    """
    
    @staticmethod
    def ensure_dir(path):
        """Crea el directorio si no existe, manejando errores de concurrencia."""
        if not os.path.exists(path):
            try:
                os.makedirs(path, exist_ok=True)
                return True
            except Exception as e:
                logging.error(f"[-] Error creando directorio {path}: {e}")
                return False
        return True

    @staticmethod
    def write_file(abs_path, content):
        """Escribe un archivo asegurando persistencia física en disco."""
        try:
            # Asegurar que el directorio padre existe
            parent = os.path.dirname(abs_path)
            FileManager.ensure_dir(parent)

            with open(abs_path, "w", encoding="utf-8") as f:
                f.write(content)
                f.flush()
                # Forzar escritura física en disco (Bypass caché de Windows)
                os.fsync(f.fileno())
            return abs_path
        except Exception as e:
            logging.error(f"[-] Error fatal de escritura en {abs_path}: {e}")
            return f"ERROR: {e}"

    @staticmethod
    def list_reports(base_dir):
        """Busca todos los archivos de reporte en el árbol de directorios."""
        reports = []
        for root, _, files in os.walk(base_dir):
            if "audit_report.md" in files:
                reports.append(os.path.join(root, "audit_report.md"))
        return reports
