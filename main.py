import sys
import asyncio
import argparse

from core.config import Config
from core.memory_cortex import MemoryCortex
from core.wordlists import WordlistManager
from core.cli.menu import CLIManager
from core.pipeline.auditor import SurgicalAuditor
from core.pipeline.campaign import CampaignManager

async def interactive_audit():
    """Flujo interactivo para auditoría única."""
    target = input("\033[1m[?] URL Objetivo: \033[0m").strip()
    if not target: return
    try:
        depth_input = input("\033[1m[?] Profundidad [1-2]: \033[0m").strip()
        depth = int(depth_input) if depth_input else 1
        depth = max(1, min(depth, 3))  # Clamp entre 1-3
    except ValueError:
        depth = 1
    
    projects = CLIManager.get_projects()
    project = None
    if projects:
        print("\n[+] Perfiles disponibles:")
        for i, p in enumerate(projects, 1): print(f"  [{i}] {p}")
        p_sel = input("[?] Seleccionar Perfil (Enter para ninguno): ").strip()
        if p_sel.isdigit() and 0 < int(p_sel) <= len(projects):
            project = projects[int(p_sel)-1]
            
    auditor = SurgicalAuditor()
    await auditor.run(target, depth=depth, project=project)

async def interactive_campaign():
    """Flujo interactivo para campaña masiva."""
    projects = CLIManager.get_projects()
    project = None
    if projects:
        print("\n[+] Perfiles disponibles:")
        for i, p in enumerate(projects, 1): print(f"  [{i}] {p}")
        p_sel = input("[?] Cargar Perfil para dominios: ").strip()
        if p_sel.isdigit() and 0 < int(p_sel) <= len(projects):
            project = projects[int(p_sel)-1]
            Config.load_project(project)
            
    domains = getattr(Config, 'TARGET_DOMAINS', [])
    if domains:
        print(f"[+] Perfil '{project}' tiene {len(domains)} dominios.")
        if input("[?] Atacar TODOS los dominios del perfil? (s/N): ").lower() != 's':
            domains = [input("[?] Dominio específico: ")]
    else:
        domains = [input("[?] Dominio para OSINT: ")]
        
    for d in [d.replace('*.','').split('/')[0] for d in domains if d]:
        campaign = CampaignManager(depth=1)
        await campaign.run(d, project)

async def main_loop():
    """Bucle principal de la aplicación."""
    while True:
        choice = CLIManager.display_menu()
        if choice == '1': await interactive_audit()
        elif choice == '2': await interactive_campaign()
        elif choice == '3':
            await WordlistManager().update_arsenal()
            input("\n[Pulse ENTER para volver]")
        elif choice in ['0', 'q', 'Q']: 
            print("\n[🛑] Saliendo de BugBot.")
            break

def main():
    """Punto de entrada atómico."""
    parser = argparse.ArgumentParser(description="BugBot Atomic Elite CLI")
    parser.add_argument("--cli", action="store_true", help="Modo No-Interactivo")
    parser.add_argument("--domain", help="Dominio para campaña masiva")
    parser.add_argument("--target", help="URL para auditoría quirúrgica")
    parser.add_argument("--slow", action="store_true", help="Activar modo sigiloso")
    parser.add_argument("--depth", type=int, default=1, choices=[1, 2, 3], help="Profundidad de crawling (1-3)")
    parser.add_argument("--reset", action="store_true", help="Limpiar bans del Cortex")
    
    args = parser.parse_args()
    
    if args.slow: Config.SLOW_MODE = True
    if args.reset: MemoryCortex().clear_all_bans()
    
    try:
        if args.cli:
            if args.domain:
                asyncio.run(CampaignManager(depth=args.depth).run(args.domain, project_name=None))
            elif args.target:
                asyncio.run(SurgicalAuditor().run(args.target, depth=args.depth))
            else:
                parser.print_help()
        else:
            asyncio.run(main_loop())
    except KeyboardInterrupt:
        print("\n\n[🛑] Cerrando BugBot.")
        sys.exit(0)

if __name__ == "__main__":
    main()
