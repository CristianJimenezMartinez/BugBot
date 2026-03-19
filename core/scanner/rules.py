# Diccionario 'Secret Hunter' & PII (AppSec Sniper Edition)
SECRET_PATTERNS = {
    # ========== CLOUD & APIs (Alta Prioridad - Zero Falsos Positivos) ==========
    # Excluye explícitamente tokens de documentación que contengan "EXAMPLE"
    "AWS Access Key": r"(?<![A-Z0-9])(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)(?!.*EXAMPLE)[A-Z0-9]{16}(?![A-Z0-9])",
    "AWS Secret Key": r"(?i)aws.{0,20}['\"](?!(?:EXAMPLE|YOUR_))[0-9a-zA-Z/+]{40}['\"]",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth ID": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "Firebase URL": r"wss?://[a-z0-9.-]+\.firebaseio\.com", # Exige el protocolo para evitar falsos en strings simples
    "Azure Storage Key": r"AccountKey=[A-Za-z0-9+/=]{88}", # Simplificado para capturar solo la llave pura
    "DigitalOcean Token": r"dop_v1_[a-f0-9]{64}",
    "Cloudflare API Token": r"(?i)(?:cloudflare|cf)[_-]?(?:token|api|key).{0,20}['\"](?!(?:EXAMPLE|YOUR_))[A-Za-z0-9_-]{40}['\"]",
    
    # ========== PAGOS Y FINANZAS (Caza Mayor) ==========
    # Incluimos 'test' porque dejar llaves de Staging en Prod es un bug válido y escalable
    "Stripe Key (Live/Test)": r"(?i)[sp]k_(?:live|test)_[0-9a-zA-Z]{24}",
    "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22}",
    "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\-_]{43}",
    "PayPal Braintree Token": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Shopify Access Token": r"shpat_[a-fA-F0-9]{32}",
    "Shopify Shared Secret": r"shpss_[a-fA-F0-9]{32}",
    
    # ========== EMAIL & MARKETING ==========
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "SendGrid API Key": r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
    "Mailchimp API Key": r"[0-9a-f]{32}-us[0-9]{1,2}",
    
    # ========== MESSAGING & BOTS ==========
    "Slack Token": r"(xox[pboaq]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9-]{24,32})", # Soporta los nuevos formatos de Slack
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,10}/B[a-zA-Z0-9_]{8,10}/[a-zA-Z0-9_]{24}",
    "Discord Bot Token": r"(?<!\w)[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}(?!\w)",
    "Discord Webhook": r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9_-]{60,68}",
    "Telegram Bot Token": r"(?<!\d)[0-9]{8,10}:[A-Za-z0-9_-]{35}(?!\w)",
    
    # ========== INFRAESTRUCTURA CRÍTICA ==========
    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "Generic Private Key": r"-----BEGIN PRIVATE KEY-----",
    # GitHub actualizado para capturar todos los Personal Access Tokens modernos (ghp, gho, ghu, ghs, ghr)
    "GitHub Token": r"(gh[pousr]_[A-Za-z0-9_]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})",
    "GitLab Token": r"glpat-[0-9A-Za-z\-_]{20}",
    "NPM Token": r"//registry\.npmjs\.org/:_authToken=[0-9a-f-]{36}",
    "Heroku API Key": r"(?i)heroku.*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "Twilio API Key": r"(?i)(?:twilio|TWILIO|account).{0,30}SK[0-9a-fA-F]{32}",
    "Twilio Account SID": r"(?i)(?:twilio|account.?sid|ACCOUNT.?SID).{0,20}AC[a-fA-F0-9]{32}",
    "LinkedIn Client Secret": r"(?i)linkedin.{0,20}secret.{0,10}['\"][0-9a-zA-Z]{16}['\"]",
    
    # ========== BASES DE DATOS (Non-Greedy & Authenticated) ==========
    # Ahora SOLO saltan si la cadena de conexión incluye usuario y contraseña reales (user:pass@)
    "MongoDB Authenticated URI": r"mongodb(?:\+srv)?://[a-zA-Z0-9_-]+:[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+",
    "PostgreSQL Authenticated URI": r"postgres(?:ql)?://[a-zA-Z0-9_-]+:[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+",
    "MySQL Authenticated URI": r"mysql://[a-zA-Z0-9_-]+:[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+",
    "Redis Authenticated URI": r"redis://(?:[a-zA-Z0-9_-]+:)?[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+",
    
    # ========== GENERIC SECRETS (Anti-Placeholder Filter) ==========
    # Filtra basura como "YOUR_API_KEY", "ENTER_TOKEN_HERE", "EXAMPLE_SECRET"
    "Generic Secret / Token": r"(?i)(?:api[_-]?key|secret|token|bearer)\s*[:=]\s*['\"](?!(?:YOUR_|ENTER_|EXAMPLE|TEST|<|>))[a-zA-Z0-9\-_]{20,}['\"]",
    "Authorization Bearer": r"(?i)authorization[\s:=]+bearer\s+(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})",
    
    # ========== PII STRICT (Reducción extrema de ruido) ==========
    # Solo atrapa JWTs reales (asegurando los 3 segmentos del base64url)
    "JWT Token": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
}