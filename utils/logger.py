import sys

class Logger:
    """Sistema de logging con colores para una apariencia profesional."""
    
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

    @staticmethod
    def info(msg):
        print(f"{Logger.BLUE}[*]{Logger.ENDC} {msg}")

    @staticmethod
    def success(msg):
        print(f"{Logger.GREEN}[+]{Logger.ENDC} {Logger.BOLD}{msg}{Logger.ENDC}")

    @staticmethod
    def warn(msg):
        print(f"{Logger.YELLOW}[!]{Logger.ENDC} {msg}")

    @staticmethod
    def error(msg):
        print(f"{Logger.RED}[-]{Logger.ENDC} {msg}")

    @staticmethod
    def banner():
        banner = f"""
{Logger.CYAN}  ____                    _            ____        _   
 | __ )  ___  _   _ _ __ | |_ _   _   | __ )  ___ | |_ 
 |  _ \ / _ \| | | | '_ \| __| | | |  |  _ \ / _ \| __|
 | |_) | (_) | |_| | | | | |_| |_| |  | |_) | (_) | |_ 
 |____/ \___/ \__,_|_| |_|\__|\__, |  |____/ \___/ \__|
                              |___/                    v1.0
{Logger.ENDC}
        """
        print(banner)
