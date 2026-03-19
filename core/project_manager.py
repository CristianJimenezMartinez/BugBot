import json
import os
import logging
from typing import Dict, Any

logger = logging.getLogger("BugBot.ProjectManager")

class ProjectManager:
    """
    Gestor de Proyectos Universal (v1.0):
    - Carga configuraciones dinámicas por programa (ProgramA, ProgramB, etc.).
    - Gestiona el Scope (In-Scope / Out-of-Scope).
    - Permite cambiar de identidad (Headers/UA) al vuelo.
    """

    DEFAULT_TEMPLATE = {
        "program_name": "Generic_Bounty",
        "hackerone_handle": "researcher",
        "custom_headers": {
            "X-Bug-Bounty": "True",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BugBot/1.0"
        },
        "target_domains": [],
        "excluded_subdomains": [],
        "interest_keywords": ["dev", "staging", "admin", "api", "conf", "secret"],
        "critical_only": False,
        "account_a_token": {"Authorization": "Bearer YOUR_TOKEN_HERE"},
        "account_b_token": {"Authorization": "Bearer YOUR_TOKEN_HERE"}
    }

    def __init__(self, projects_dir: str = "projects"):
        self.projects_dir = projects_dir
        if not os.path.exists(self.projects_dir):
            os.makedirs(self.projects_dir, exist_ok=True)
        self.current_config = self.DEFAULT_TEMPLATE.copy()

    def create_project(self, name: str, data: Dict[str, Any]):
        """Crea un nuevo perfil de programa."""
        path = os.path.join(self.projects_dir, f"{name}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        logger.info(f"Proyecto {name} creado con éxito.")

    def load_project(self, name: str) -> bool:
        """Carga la configuración de un proyecto específico."""
        path = os.path.join(self.projects_dir, f"{name}.json")
        if not os.path.exists(path):
            logger.error(f"Error: El proyecto {name} no existe.")
            return False
            
        with open(path, "r", encoding="utf-8") as f:
            user_config = json.load(f)
            # Combinar con el template por defecto por seguridad
            self.current_config = {**self.DEFAULT_TEMPLATE, **user_config}
            
        logger.info(f"Proyecto {name} cargado correctamente.")
        return True

    def is_in_scope(self, url: str) -> bool:
        """Valida si una URL o host está dentro del alcance definido."""
        from urllib.parse import urlparse
        domain = urlparse(url).netloc if "://" in url else url
        
        # Check exclusion
        for excluded in self.current_config["excluded_subdomains"]:
            if excluded in domain:
                return False
                
        # Check inclusion
        for target in self.current_config["target_domains"]:
            if target in domain:
                return True
                
        return False

if __name__ == "__main__":
    # Test rápido
    pm = ProjectManager()
    pm.create_project("example_program", {
        "program_name": "Example_H1",
        "hackerone_handle": "researcher",
        "target_domains": ["example.com", "test.com"],
        "excluded_subdomains": ["out-of-scope.example.com"]
    })
    if pm.load_project("example_program"):
        print(f"Cargado: {pm.current_config['program_name']}")
        print(f"¿In Scope (api.example.com)? {pm.is_in_scope('api.example.com')}")
        print(f"¿In Scope (evil.com)? {pm.is_in_scope('evil.com')}")
