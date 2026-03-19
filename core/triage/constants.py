# Reglas Atómicas de Triaje (Anti-Ruido y Severidades)

# 1. Rutas de archivos a ignorar (Docs, Tests, Mocks)
IGNORED_PATHS = r'(?i)(README\.md|LICENSE|CHANGELOG|test/|tests/|spec/|mock_|\.github/|docs/|example|sample|node_modules|vendor/)'

# 2. Librerías de terceros, CDNs y Widgets (Falsos Positivos Masivos)
THIRD_PARTY_LIBS = (
    r'(?i)(jquery[\.\-]|bootstrap\.min|react\.production|react-dom\.production|angular\.min|lodash[\.\-]|moment\.min|polyfill\.io|'
    r'chunk-vendors\.js|runtime~main|cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com|unpkg\.com|'
    r'gsap\.min\.js|anime\.min\.js|three\.min\.js|scrolltrigger\.min\.js|'
    r'googletagmanager\.com|google-analytics\.com|googleadservices\.com|'
    r'bat\.bing\.com|taboola\.com|connect\.facebook\.net|hotjar\.com|pagesense\.io|'
    r'cdn\.segment\.com|api\.segment\.io|'
    r'cdn\.amplitude\.com|cdn\.mixpanel\.com|heapanalytics\.com|'
    r'crazyegg\.com|fullstory\.com|cdn\.logrocket\.com|'
    r'cdn\.optimizely\.com|abtasty\.com|dev\.visualwebsiteoptimizer\.com|'
    r'cdn\.cookielaw\.org|consent\.cookiebot\.com|iubenda\.com|'
    r'wix-thunderbolt|parastorage\.com|wp-includes/|wp-content/themes/|'
    r'cdn\.shopify\.com|static\.squarespace\.com|assets\.squarespace\.com|'
    r'assets-global\.website-files\.com|cdn\.webflow\.com|'
    r'gstatic\.com|googleapis\.com|googleusercontent\.com|challenges\.cloudflare\.com|'
    r'msauth\.net|msftauth\.net|cdn\.auth0\.com|cdn\.okta\.com|cdn\.onelogin\.com|'
    r'js\.hs-scripts\.com|js\.hs-banner\.com|js\.hs-analytics\.net|js\.hscollectedforms\.net|'
    r'widget\.intercom\.io|js\.intercomcdn\.com|'
    r'static\.zdassets\.com|ekr\.zdassets\.com|'
    r'client\.crisp\.chat|embed\.tawk\.to|cdn\.livechatinc\.com|js\.driftt\.com|'
    r'pardot\.com|munchkin\.marketo\.net|'
    r'vimeocdn\.com|player\.vimeo\.com|youtube\.com/iframe_api|s\.ytimg\.com|'
    r'browser\.sentry-cdn\.com|js-agent\.newrelic\.com|bam\.nr-data\.net|'
    r'rum\.browser-intake-datadoghq\.com|'
    r'cdn\.appdynamics\.com|js-cdn\.dynatrace\.com|'
    r'use\.typekit\.net|fonts\.gstatic\.com|'
    r'github\.githubassets\.com|raw\.githubusercontent\.com)'
)

# 3. Directorios estáticos públicos
STATIC_DIRS = r'(?i)^https?://[^/]+/(js|css|images|img|assets|common|static|fonts|public)/?$'

# 4. Contexto de documentación genérica
IGNORED_CONTEXT = r'(?i)(TODO|example:|# test|fake_key|YOUR_API_KEY|insert_token_here|dummy_secret|placeholder|xxx_key_here|REPLACE_ME|change_this|put_your)'

# 5. Enlaces a repositorios públicos
GITHUB_NOISE = r'(?i)(github\.com/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+|raw\.githubusercontent\.com|gist\.github\.com)'

# 6. Severidades Estándar (CVSS Base)
SEVERITIES = {
    "WAF_BYPASSED": "Medium",
    "IDOR_READ": "High",
    "IDOR_WRITE": "Critical",
    "SOURCE_MAP_DISCLOSURE": "Low",
    "AWS_KEY_EXPOSED": "Critical",
    "RSA_PRIVATE_KEY": "Critical",
    "GRAPHQL_INTROSPECTION": "Medium",
    "CLOUD_BUCKET": "High",
    "TAKEOVER": "Critical",
    "SECRET": "High",
    "SENSITIVE_FILE": "Low"
}
