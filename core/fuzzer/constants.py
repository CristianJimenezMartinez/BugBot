import random

# User-Agents Tácticos
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
]

# Diccionario 'Sniper' (WordPress e Infraestructura)
SENSITIVE_FILES = [
    # Arquitectura & Cloud
    ".env", ".env.bak", ".env.old", ".env.example", ".git/config", ".git/index",
    ".svn/entries", ".vscode/sftp.json", ".aws/credentials", "firebase.json",
    "docker-compose.yml", "Dockerfile", "web.config", ".htaccess",
    
    # WordPress Pro
    "wp-config.php.bak", "wp-config.php.swp", "wp-json/wp/v2/users", 
    "debug.log", "wp-admin/admin-ajax.php",
    
    # Backups & Logs
    ".bash_history", "config.zip", "backup.sql", "database.sql", "db.sql", "dump.sql",
    "www.tar.gz", "backup.zip", "data.zip", "db.zip", "archive.zip",
    
    # API & Config
    "swagger-ui.html", "phpinfo.php", "config.php", "config.php.bak",
    "package-lock.json", "composer.json", "npm-debug.log",
    "robots.txt", "sitemap.xml", ".well-known/security.txt"
]

# 🎯 Diccionario de Ataque Universal para APIs e Infraestructura Corporativa
CRITICAL_API_ENDPOINTS = [
    # ========== ServiceNow ==========
    '/api/now/table/sys_user',             # Tabla de empleados/usuarios (Fuga de PII)
    '/api/now/table/incident',             # Tickets de soporte internos
    '/api/now/table/kb_knowledge',         # Base de conocimientos
    '/api/now/v1/table/sys_properties',    # Configuración del sistema
    '/api/now/sp/widget',                  # Widgets del Service Portal
    '/api/now/table/sys_email',            # Correos internos interceptados
    
    # ========== API Discovery (Swagger/OpenAPI/GraphQL) ==========
    '/api/swagger.json',
    '/swagger.json',
    '/swagger/v1/swagger.json',
    '/v2/api-docs',                        # Spring Boot Swagger v2
    '/v3/api-docs',                        # Spring Boot OpenAPI v3
    '/api/graphql',
    '/graphql',
    '/api/v1/docs',
    '/redoc',
    '/.well-known/openid-configuration',
    
    # ========== DevOps / CI-CD ==========
    '/jenkins/script',                     # Jenkins Script Console (RCE!)
    '/jenkins/api/json',                   # Jenkins API sin auth
    '/api/v4/projects',                    # GitLab API
    '/api/v4/users',                       # GitLab Users
    '/_catalog',                           # Docker Registry
    '/v2/_catalog',                        # Docker Registry v2
    
    # ========== Kubernetes ==========
    '/api/v1/namespaces',
    '/api/v1/pods',
    '/api/v1/secrets',                     # K8s Secrets (JACKPOT)
    '/api/v1/configmaps',
    '/apis/apps/v1/deployments',
    '/healthz',
    '/version',
    
    # ========== Bases de Datos Expuestas ==========
    '/_all_docs',                          # CouchDB
    '/_config',                            # CouchDB config
    '/_cat/indices',                       # Elasticsearch
    '/_cluster/health',                    # Elasticsearch
    '/_search?q=*',                        # Elasticsearch query
    '/solr/admin/cores',                   # Apache Solr
    
    # ========== Monitoring & Observability ==========
    '/actuator/health',                    # Spring Boot
    '/actuator/env',                       # Spring Boot (passwords!)
    '/actuator/configprops',               # Spring Boot config
    '/actuator/mappings',                  # Spring Boot routes map
    '/server-status',                      # Apache
    '/nginx_status',                       # Nginx
    '/server-info',                        # Apache
    
    # ========== Admin Panels ==========
    '/phpmyadmin/',
    '/adminer.php',
    '/wp-json/wp/v2/users',                # WordPress REST: User Enum
    '/wp-json/wp/v2/pages',
    '/rest/api/2/myself',                  # Jira
    '/rest/api/2/serverInfo',              # Jira Server Info
    '/rest/api/content',                   # Confluence
    '/api/v1/auth/login',                  # Auth endpoints genéricos
    '/api/system/status',
    '/grafana/api/dashboards/home',        # Grafana
    '/api/datasources',                    # Grafana datasources
    '/app/kibana',                         # Kibana
    '/api/status',                         # Kibana status
    
    # ========== Cloud Storage Misconfig ==========
    '/s3/',
    '/.well-known/security.txt',
    '/crossdomain.xml',
    '/clientaccesspolicy.xml'
]

def get_random_ua() -> str:
    return random.choice(USER_AGENTS)
