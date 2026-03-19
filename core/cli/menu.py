import os
from typing import List
from core.project_manager import ProjectManager
from core.cli.banners import BANNER

class CLIManager:
    """Gestor atómico para la interfaz de usuario de BugBot."""
    
    @staticmethod
    def clear_screen():
        os.system('cls' if os.name == 'nt' else 'clear')

    @staticmethod
    def get_projects() -> List[str]:
        pm = ProjectManager()
        if not os.path.exists(pm.projects_dir): return []
        return [f.replace('.json', '') for f in os.listdir(pm.projects_dir) if f.endswith('.json')]

    @staticmethod
    def display_menu() -> str:
        """Muestra el arsenal de BugBot."""
        CLIManager.clear_screen()
        print(BANNER)
        print("\n\033[1m[+] ARMAMENTO DISPONIBLE:\033[0m")
        print("  \033[96m[1]\033[0m Asalto Quirúrgico (Objetivo Específico)")
        print("  \033[96m[2]\033[0m Campaña Masiva OSINT (Extraer y Atacar Subdominios)")
        print("  \033[96m[3]\033[0m Actualizar Diccionarios Tácticos (SecLists)")
        print("  \033[96m[0]\033[0m Salir")
        try:
            return input("\n\033[1m[?] Selecciona tu arma (0-3): \033[0m")
        except (EOFError, KeyboardInterrupt):
            return "0"
