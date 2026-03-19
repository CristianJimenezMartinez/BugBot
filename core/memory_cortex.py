import sqlite3
import os
import json
import logging
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from urllib.parse import urlparse
from core.config import Config

logger = logging.getLogger("BugBot.MemoryCortex")

class MemoryCortex:
    """
    Fase 7: El Cerebro Persistente de BugBot.
    Almacena en una base de datos local SQLite:
    - Host/IPs que nos han bloqueado (WAF Bans temporales).
    - Patrones de inyección que funcionan en ciertos contextos.
    - Parámetros ocultos útiles conocidos.
    """
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(MemoryCortex, cls).__new__(cls)
            cls._instance._init_db()
        return cls._instance

    def _init_db(self):
        os.makedirs(Config.DATA_DIR, exist_ok=True)
        self.db_path = os.path.join(Config.DATA_DIR, "bugbot_brain.db")
        self._lock = threading.Lock()  # Mutex para escrituras concurrentes
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging
        self.cursor = self.conn.cursor()
        
        # 1. Purga de memoria vieja al arrancar
        self.purge_old_memory()
        
        # Tabla de Bloqueos de WAF
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS waf_bans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE,
                ban_timestamp REAL,
                waf_type TEXT,
                severity INTEGER
            )
        ''')
        
        # Tabla de Parámetros Sensibles / Exitosos
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS known_parameters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT,
                param_name TEXT,
                vulnerability_type TEXT,
                last_seen REAL,
                UNIQUE(domain, param_name)
            )
        ''')

        # [ELITE] Tabla de Rutas Críticas / Exitosas
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS known_paths (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT,
                path TEXT,
                vulnerability_type TEXT,
                last_seen REAL,
                UNIQUE(domain, path)
            )
        ''')
        
        # Tabla de Mapeo de E/S (Filesystem Mirrors & Virtualization)
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_paths (
                path_type TEXT PRIMARY KEY,
                absolute_path TEXT,
                last_verified REAL
            )
        ''')
        
        # Tabla de Hallazgos (Flood Control Estructural)
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                type TEXT,
                timestamp REAL
            )
        ''')
        
        self.conn.commit()
        
        # Auto-registro de las rutas actuales en el arranque
        self.validate_system_io()

    def validate_system_io(self):
        """Mapea las rutas reales del contenedor/OS y las registra para módulos ciegos."""
        logger.info(f"[🧠 CORTEX] Auditando Rutas del Sistema:")
        logger.info(f"   -> BASE_DIR: {os.path.abspath(Config.BASE_DIR)}")
        logger.info(f"   -> DATA_DIR: {os.path.abspath(Config.DATA_DIR)}")
        
        self.record_workspace_path("base_dir", Config.BASE_DIR)
        self.record_workspace_path("data_dir", Config.DATA_DIR)
        self.record_workspace_path("targets_dir", Config.TARGETS_DIR)

    def purge_old_memory(self):
        """[MAINTENANCE] Limpia registros antiguos para evitar crecimiento infinito de la DB."""
        with self._lock:
            try:
                # 1. Borrar bans de WAF más antiguos de 24 horas (86400s)
                self.cursor.execute("DELETE FROM waf_bans WHERE ban_timestamp < ?", (time.time() - 86400,))
                
                # 2. Borrar findings de más de 7 días (604800s)
                self.cursor.execute("DELETE FROM findings WHERE timestamp < ?", (time.time() - 604800,))
                
                self.conn.commit()
                logger.info("[🧠 CORTEX] Purga de mantenimiento completada exitosamente.")
            except Exception as e:
                logger.error(f"[Cortex Error] Purga: {e}")

    def record_workspace_path(self, path_type: str, absolute_path: str):
        """Guarda o actualiza la ubicación física de un recurso vital."""
        with self._lock:
            try:
                self.cursor.execute('''
                    INSERT INTO system_paths (path_type, absolute_path, last_verified)
                    VALUES (?, ?, ?)
                    ON CONFLICT(path_type) DO UPDATE SET 
                    absolute_path=excluded.absolute_path, last_verified=excluded.last_verified
                ''', (path_type, absolute_path, time.time()))
                self.conn.commit()
            except Exception:
                pass

    def get_workspace_path(self, path_type: str) -> Optional[str]:
        """Obtiene una ruta validada previamente por el Cortex (útil en Dockers aislados)."""
        self.cursor.execute('SELECT absolute_path FROM system_paths WHERE path_type=?', (path_type,))
        row = self.cursor.fetchone()
        return row[0] if row else None

    def record_waf_ban(self, domain: str, waf_type: str = "Cloudflare", severity: int = 1, custom_cooldown: int = 1800):
        """Registra un bloqueo del WAF con enfriamiento dinámico (default 30 min)."""
        if self.is_currently_banned(domain):
            return

        with self._lock:
            try:
                ban_timestamp = time.time()
                self.cursor.execute('''
                    INSERT INTO waf_bans (domain, ban_timestamp, waf_type, severity)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(domain) DO UPDATE SET 
                    ban_timestamp=excluded.ban_timestamp, severity=severity+1
                ''', (domain, ban_timestamp, waf_type, severity))
                self.conn.commit()
                
                exp_time = (datetime.now() + timedelta(minutes=30)).strftime("%H:%M:%S")
                logger.warning(f"[🧠 CORTEX] Bloqueo detectado en {domain} ({waf_type}). Enfriando hasta {exp_time} (1800s).")
                print(f"\n\033[91m[🧠 CORTEX] Re-WAF: Bloqueo en {domain} ({waf_type}). Enfriando hasta {exp_time} (1800s).\033[0m")
            except Exception as e:
                logger.debug(f"[Cortex Error] {e}")

    def is_currently_banned(self, domain: str, default_cooldown: int = 1800) -> bool:
        """Verifica si un host nos tiene baneados actualmente."""
        try:
            # No necesitamos lock para lecturas simples en SQLite con WAL
            self.cursor.execute('SELECT ban_timestamp FROM waf_bans WHERE domain=?', (domain,))
            row = self.cursor.fetchone()
            if row:
                if (time.time() - row[0]) < default_cooldown:
                    return True
        except Exception:
            pass
        return False

    def clear_all_bans(self):
        """Limpia todos los bloqueos actuales de la base de datos."""
        with self._lock:
            self.cursor.execute("DELETE FROM waf_bans")
            self.conn.commit()
            logger.info("[🧠 CORTEX] Memoria de bloqueos reseteada (Cero Baneos).")

    def remember_vulnerable_param(self, domain: str, param_name: str, vuln_type: str):
        """Memoriza parámetros jugosos para campañas futuras sobre la misma infraestructura."""
        with self._lock:
            try:
                self.cursor.execute('''
                    INSERT INTO known_parameters (domain, param_name, vulnerability_type, last_seen)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(domain, param_name) DO UPDATE SET last_seen=excluded.last_seen
                ''', (domain, param_name, vuln_type, time.time()))
                self.conn.commit()
                logger.info(f"[🧠 CORTEX] Aprendiendo nuevo vector (PARAM): {param_name} en {domain}")
            except Exception as e:
                pass

    def remember_vulnerable_path(self, domain: str, path: str, vuln_type: str):
        """[ELITE] Memoriza rutas críticas que han dado positivo (ej: /api/v1/debug)."""
        with self._lock:
            try:
                self.cursor.execute('''
                    INSERT INTO known_paths (domain, path, vulnerability_type, last_seen)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(domain, path) DO UPDATE SET last_seen=excluded.last_seen
                ''', (domain, path, vuln_type, time.time()))
                self.conn.commit()
                logger.info(f"[🧠 CORTEX] Aprendiendo nuevo vector (PATH): {path} en {domain}")
            except Exception as e:
                pass

    def get_known_params_for_domain(self, domain: str) -> List[str]:
        """Obtiene la lista de parámetros previamente explotables en el dominio."""
        self.cursor.execute('SELECT DISTINCT param_name FROM known_parameters WHERE domain=?', (domain,))
        return [row[0] for row in self.cursor.fetchall()]

    def get_known_paths_for_domain(self, domain: str) -> List[str]:
        """Obtiene la lista de rutas previamente explotables en el dominio."""
        self.cursor.execute('SELECT DISTINCT path FROM known_paths WHERE domain=?', (domain,))
        return [row[0] for row in self.cursor.fetchall()]

    def get_all_global_intelligence(self) -> Dict[str, List[str]]:
        """[EXPERIMENTAL] Obtiene todos los parámetros y rutas exitosas de CUALQUIER dominio para compartirlos."""
        self.cursor.execute('SELECT DISTINCT param_name FROM known_parameters')
        params = [row[0] for row in self.cursor.fetchall()]
        self.cursor.execute('SELECT DISTINCT path FROM known_paths')
        paths = [row[0] for row in self.cursor.fetchall()]
        return {"params": params, "paths": paths}

    # Limitador de Ruido Estructural (Flood Control)
    MAX_ALERTS_PER_FILE = 5

    def should_store_finding(self, target_url: str, vulnerability_type: str) -> bool:
        """
        Evita que un solo archivo envenene la base de datos (Flood Control).
        Usa el PATH en lugar de la URL completa para evitar duplicados entre subdominios.
        """
        path = urlparse(target_url).path
        if not path: path = "/"

        with self._lock:
            try:
                self.cursor.execute(
                    "SELECT COUNT(*) FROM findings WHERE url = ? AND type = ?", 
                    (path, vulnerability_type)
                )
                count = self.cursor.fetchone()[0]
                
                if count >= self.MAX_ALERTS_PER_FILE:
                    return False 
                
                self.cursor.execute(
                    "INSERT INTO findings (url, type, timestamp) VALUES (?, ?, ?)",
                    (path, vulnerability_type, time.time())
                )
                self.conn.commit()
                return True
            except Exception as e:
                logger.error(f"[Cortex Error] Flood Control: {e}")
                return True

    def close(self):
        if self.conn:
            self.conn.close()

# Ejemplo de uso independiente
if __name__ == "__main__":
    cortex = MemoryCortex()
    cortex.record_waf_ban("api.playtika.com")
    print("Ban activo?", cortex.is_currently_banned("api.playtika.com"))
    cortex.remember_vulnerable_param("news.playtika.com", "debug", "Information Disclosure")
    print("Parametros en news:", cortex.get_known_params_for_domain("news.playtika.com"))
