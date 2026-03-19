import os

class Config:
    """
    Configuración Central BugBot v1.1
    - Centraliza rutas, límites y credenciales.
    """
    
    # Rutas del Sistema (Dinámicas y Relativas al Entorno Virtualizado)
    # Detecta dónde está el bot sin importar si es Windows, Linux, WSL o Docker.
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    TARGETS_DIR = os.path.join(BASE_DIR, "targets")
    LOGS_DIR = os.path.join(BASE_DIR, "logs")
    DATA_DIR = os.path.join(BASE_DIR, "data") # Inteligencia Global & Diccionarios
    
    # Hit List Global (Sigue en data para persistencia)
    HIT_LIST_PATH = os.path.join(DATA_DIR, "GLOBAL_HIT_LIST.md")

    GLOBAL_CONCURRENCY = 10  # Peticiones simultáneas globales
    MODULE_CONCURRENCY = 3   # Peticiones por módulo (Ultra-Safe)
    TIMEOUT = 15             # Segundos de espera para navegación normal
    TIMEOUT_OOB = 30         # Segundos de espera para inyecciones ciegas/SSRF
    SLOW_MODE = False        # Activa esperas adicionales entre peticiones
    
    # Adaptive Rate Limiting
    _rate_multiplier = 1.0   # Se ajusta dinámicamente con 429s
    _consecutive_ok = 0      # Contador de respuestas exitosas consecutivas

    @classmethod
    def register_rate_event(cls, status_code: int):
        """Ajusta el rate limiting dinámicamente según respuestas del servidor."""
        if status_code in [429, 503]:
            cls._rate_multiplier = min(cls._rate_multiplier * 2.0, 10.0)
            cls._consecutive_ok = 0
        elif status_code < 400:
            cls._consecutive_ok += 1
            if cls._consecutive_ok > 20 and cls._rate_multiplier > 1.0:
                cls._rate_multiplier = max(cls._rate_multiplier * 0.8, 1.0)
                cls._consecutive_ok = 0

    @classmethod
    def get_jitter(cls):
        """Retorna un retraso aleatorio adaptativo."""
        import random
        if cls.SLOW_MODE:
            base = random.uniform(1.2, 3.5)
        else:
            base = random.uniform(0.1, 0.4)
        return base * cls._rate_multiplier

    # Identidad y Evasión (Rotación Activa)
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.2277.83",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
    ]
    
    @classmethod
    def get_random_user_agent(cls) -> str:
        import random
        return random.choice(cls.USER_AGENTS)
        
    CUSTOM_HEADERS = {
        "X-HackerOne-Research": "username=researcher", # Formato estándar de la industria
        "X-Bug-Bounty": "True",
        "User-Agent": "BugBot-Hunter/4.0 (Authorized Security Research)" # Doble verificación
    }
    
    # 🚫 Lista Negra (Out of Scope - Cumplimiento de Reglas)
    # NOTA: Todos los wildcards (*.example.com, etc.) están IN SCOPE.
    # Solo añadir aquí dominios EXPLÍCITAMENTE excluidos por el programa de Bug Bounty.
    OUT_OF_SCOPE_DOMAINS = []

    TARGET_DOMAINS = []

    @classmethod
    def load_project(cls, project_name):
        """Sobrescribe la configuración estática con la del proyecto dinámico."""
        from core.project_manager import ProjectManager
        pm = ProjectManager()
        if pm.load_project(project_name):
            config = pm.current_config
            cls.CUSTOM_HEADERS = config.get("custom_headers", cls.CUSTOM_HEADERS)
            cls.INTEREST_KEYWORDS = config.get("interest_keywords", cls.INTEREST_KEYWORDS)
            cls.TARGET_DOMAINS = config.get("target_domains", [])
            # Overrides de Rendimiento (Anti-DoS / Slow Mode)
            cls.GLOBAL_CONCURRENCY = config.get("global_concurrency", cls.GLOBAL_CONCURRENCY)
            cls.MODULE_CONCURRENCY = config.get("module_concurrency", cls.MODULE_CONCURRENCY)
            print(f"[*] Configuración cargada del perfil: {project_name}")
            if cls.MODULE_CONCURRENCY <= 2:
                print(f"   [!] MODO SILENCIOSO ACTIVADO (Concurrencia: {cls.MODULE_CONCURRENCY})")
            return True
        return False

    # Recon Intel
    # Prioridad Alta: dev, staging, qa, internal, admin, api, git, jenkins, jira, octopus, preprod
    # Prioridad Media: vpn, mail, portal, test, beta, old
    # Submisión Crítica Requerida: justfall.lol, justplay.lol
    INTEREST_KEYWORDS = [
        "dev", "staging", "test", "qa", "internal", "admin", "api", 
        "git", "jenkins", "jira", "octopus", "preprod", "old", "beta", "vpn", "mail", "portal",
        "aws", "s3", "bucket", "config", "secret", "token", "password"
    ]

    BRUTE_FORCE_LIST = [
        "dev", "staging", "test", "api", "admin", "vpn", "mail", "internal", "git", 
        "jenkins", "jira", "portal", "dev-api", "qa", "prod", "beta", "old", "stage",
        "m", "mobile", "app", "dashboard", "cdn", "static", "img", "assets", "store",
        "shop", "api-dev", "api-staging", "auth", "login", "sso", "search", "mailman",
        "webmail", "blog", "cloud", "ns1", "ns2", "support", "help", "docs", "beta-api",
        "svn", "gitlab", "bitbucket", "docker", "k8s", "prometheus", "grafana", "monitor",
        "status", "security", "infra", "network", "gateway", "proxy", "edge", "aws", "s3",
        "testing", "sandbox", "uat", "preprod", "octopus", "teamcity", "bamboo", "confluence"
    ]

    @staticmethod
    def get_connector():
        """Retorna un conector de aiohttp seguro para Windows (evita conflictos con aiodns)."""
        import aiohttp
        import sys
        if sys.platform == 'win32':
            return aiohttp.TCPConnector(resolver=aiohttp.ThreadedResolver(), use_dns_cache=False)
        return aiohttp.TCPConnector()

    @staticmethod
    def setup_logger(name, log_file, level="INFO"):
        """Configura un logger específico con su propio manejador de archivo."""
        import logging
        logger = logging.getLogger(name)
        if not logger.handlers:
            logger.setLevel(getattr(logging, level.upper()))
            path = os.path.join(Config.LOGS_DIR, log_file)
            handler = logging.FileHandler(path, encoding='utf-8')
            formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            # Evitar propagación al root logger para no duplicar en logs ajenos
            logger.propagate = False
        return logger

    @staticmethod
    def get_target_path(domain):
        """Genera la ruta absoluta sanitizada para un dominio, sin importar si viene con protocolo."""
        from urllib.parse import urlparse
        # Si nos pasan la URL con https:// por error, extraemos solo el domain
        clean_domain = urlparse(domain).netloc if "://" in domain else domain
        # Si netloc falla, usamos el domain original pero quitamos caracteres ilegales
        if not clean_domain: clean_domain = domain
        
        # Sanitizar para Windows (quitar : / \ * ? " < > |)
        illegal_chars = [':', '/', '\\', '*', '?', '"', '<', '>', '|']
        for char in illegal_chars:
            clean_domain = clean_domain.replace(char, "_")
            
        folder_name = clean_domain.replace(".", "_")
        return os.path.abspath(os.path.join(Config.TARGETS_DIR, folder_name))
