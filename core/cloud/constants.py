# Configuración de Cloud Hunter (Foco Corporativo/Europeo)

PERMUTATIONS = [
    "dev", "development", "test", "testing", "qa", "staging", "prod", "production",
    "backup", "backups", "bak", "archive", "logs", "data", "database", "db",
    "assets", "static", "media", "images", "img", "video", "cdn",
    "internal", "private", "secret", "conf", "config", "admin", "api", "web",
    "old", "new", "v1", "v2", "beta", "demo", "public", "uploads", "files",
    "shop", "checkout", "mzp", "zootopia", "customer", "billing", "inventory"
]

DELIMITERS = ["-", "_", ".", ""]

GENERIC_IGNORE_LIST = {
    'autodiscover', 'mail', 'www', 'ftp', 'cpanel', 'webmail', 
    'smtp', 'pop3', 'imap', 'ns1', 'ns2', 'm', 'mobile'
}

CLOUD_REGIONS = ['eu-central-1', 'eu-west-1', 'us-east-1']
