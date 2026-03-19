# Configuración de File Analyzer Atomic

INTERESTING_EXTENSIONS = [
    '.zip', '.tar', '.tar.gz', '.tgz', '.gz', # Comprimidos
    '.sql', '.db', '.sqlite', '.bak', '.dump', # Bases de datos
    '.env', '.config', '.ini', '.yaml', '.yml', '.json', # Configuración
    '.key', '.pem', '.crt', '.p12', '.pfx', # Criptografía
    '.log', '.txt' # Logs
]

EXT_CATEGORIES = {
    'archives': ['.zip', '.tar', '.tar.gz', '.tgz', '.gz'],
    'databases': ['.sql', '.db', '.sqlite', '.bak', '.dump'],
    'configs': ['.env', '.config', '.ini', '.yaml', '.yml', '.json'],
    'crypto': ['.key', '.pem', '.crt', '.p12', '.pfx'],
    'logs': ['.log', '.txt']
}
