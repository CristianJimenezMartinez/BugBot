import re
import logging
from typing import List, Dict
from core.scanner.rules import SECRET_PATTERNS

logger = logging.getLogger("BugBot.Scanner.Analyzer")

class ContentAnalyzer:
    """Motor atómico de análisis de contenido y detección de secretos."""
    
    @staticmethod
    def scan_content(url: str, content: str) -> List[Dict]:
        """Analiza el contenido con Inteligencia 'No-Noise' (v1.1)."""
        local_findings = []
        lines = content.splitlines()
        
        # Filtros de Vendors (Playtika Compliance)
        ignored_domains = ["@sentry.io", "@braze.com", "@google.com", "@faisalman.com"]
        noise_keywords = ["webpack_require", "chunkid", "integrity=", "type=\"password\"", "placeholder=", "node_modules", "<svg", "license"]

        for secret_type, pattern in SECRET_PATTERNS.items():
            for line in lines:
                context = line.lower()
                
                # [Intelligence] Filtro de Ruido de UI / Webpack / SVG
                if any(noise in context for noise in noise_keywords):
                    continue
                
                # [Intelligence] Filtro Sentry Ingest ID
                if "ingest.sentry.io" in url.lower():
                    continue

                # Buscamos matches
                matches = re.finditer(pattern, line)
                for m in matches:
                    match_str = m.group()
                    
                    # 1. Filtro 'No-Noise' Matemático (Decimales o Potencias)
                    if secret_type == "PII: Credit Card" or re.fullmatch(r"\d{16}", match_str):
                        start_idx = m.start()
                        # Verificamos si hay un punto decimal o '**' delante
                        prefix = line[max(0, start_idx-2):start_idx]
                        if "." in prefix or "**" in prefix:
                            continue

                    # 2. Filtro de Domains Vendor
                    if secret_type == "PII: Email Exposed":
                        if any(domain in match_str.lower() for domain in ignored_domains):
                            continue

                    # 3. Filtro Sentry/Ingest Contextual
                    if re.fullmatch(r"\d{16}", match_str) and ("sentry" in context or "ingest" in context):
                        continue
                        
                    # 4. Filtro Cloudflare (Anti-Hex-Hash)
                    if secret_type == "Cloudflare API Token":
                        # Si es puro Hex de 40 carácteres, es probablemente un Git Hash o Build ID
                        if re.fullmatch(r"[a-f0-9]{40}", match_str):
                            continue

                    evidence = f"Valor: `{match_str}` | Contexto: `...{line[max(0, m.start()-20):min(len(line), m.end()+20)].replace('\\n', ' ')}...`"
                    
                    local_findings.append({
                        'url_archivo': url,
                        'tipo_secreto': secret_type,
                        'match': match_str,
                        'evidence': {secret_type: [evidence]}
                    })
        
        return local_findings

    @staticmethod
    async def validate_google_key(session, key: str) -> bool:
        """Active Validation: Ping a Google Maps API para ver si la llave tiene saldo."""
        test_url = f"https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key={key}"
        try:
            async with session.get(test_url, timeout=5) as response:
                if response.status == 200:
                    return True
        except Exception:
            pass
        return False

    @staticmethod
    async def validate_aws_key(session, access_key: str, secret_key: str) -> dict:
        """Active Validation: AWS STS GetCallerIdentity (read-only, zero side effects)."""
        import hmac, hashlib
        from datetime import datetime, timezone
        try:
            now = datetime.now(timezone.utc)
            datestamp = now.strftime('%Y%m%d')
            amz_date = now.strftime('%Y%m%dT%H%M%SZ')
            region = 'us-east-1'
            service = 'sts'
            host = 'sts.amazonaws.com'
            
            # AWS Signature V4
            canonical_uri = '/'
            canonical_querystring = 'Action=GetCallerIdentity&Version=2011-06-15'
            canonical_headers = f'host:{host}\nx-amz-date:{amz_date}\n'
            signed_headers = 'host;x-amz-date'
            payload_hash = hashlib.sha256(b'').hexdigest()
            canonical_request = f'GET\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}'
            
            algorithm = 'AWS4-HMAC-SHA256'
            credential_scope = f'{datestamp}/{region}/{service}/aws4_request'
            string_to_sign = f'{algorithm}\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode()).hexdigest()}'
            
            def sign(key, msg):
                return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()
            
            signing_key = sign(sign(sign(sign(f'AWS4{secret_key}'.encode('utf-8'), datestamp), region), service), 'aws4_request')
            signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
            
            authorization = f'{algorithm} Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}'
            
            headers = {
                'x-amz-date': amz_date,
                'Authorization': authorization,
                'Host': host
            }
            
            url = f'https://{host}/?{canonical_querystring}'
            async with session.get(url, headers=headers, timeout=8) as response:
                body = await response.text()
                if response.status == 200 and 'GetCallerIdentityResult' in body:
                    # Extraer Account ID y ARN
                    import re
                    account = re.search(r'<Account>(\d+)</Account>', body)
                    arn = re.search(r'<Arn>([^<]+)</Arn>', body)
                    return {
                        "valid": True,
                        "account_id": account.group(1) if account else "Unknown",
                        "arn": arn.group(1) if arn else "Unknown"
                    }
        except Exception:
            pass
        return {"valid": False}

    @staticmethod
    async def validate_stripe_key(session, key: str) -> dict:
        """Active Validation: Stripe GET /v1/balance (read-only)."""
        try:
            import base64
            auth = base64.b64encode(f"{key}:".encode()).decode()
            headers = {"Authorization": f"Basic {auth}"}
            async with session.get("https://api.stripe.com/v1/balance", headers=headers, timeout=8) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "valid": True,
                        "livemode": data.get("livemode", False),
                        "currency": data.get("available", [{}])[0].get("currency", "unknown")
                    }
        except Exception:
            pass
        return {"valid": False}

    @staticmethod
    async def validate_slack_token(session, token: str) -> dict:
        """Active Validation: Slack auth.test (read-only)."""
        try:
            headers = {"Authorization": f"Bearer {token}"}
            async with session.get("https://slack.com/api/auth.test", headers=headers, timeout=8) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get("ok"):
                        return {
                            "valid": True,
                            "team": data.get("team", "Unknown"),
                            "user": data.get("user", "Unknown"),
                            "team_id": data.get("team_id", "")
                        }
        except Exception:
            pass
        return {"valid": False}

    @staticmethod
    async def validate_github_token(session, token: str) -> dict:
        """Active Validation: GitHub GET /user (read-only)."""
        try:
            headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
            async with session.get("https://api.github.com/user", headers=headers, timeout=8) as response:
                if response.status == 200:
                    data = await response.json()
                    scopes = response.headers.get("X-OAuth-Scopes", "none")
                    return {
                        "valid": True,
                        "user": data.get("login", "Unknown"),
                        "scopes": scopes,
                        "name": data.get("name", "")
                    }
        except Exception:
            pass
        return {"valid": False}

    @staticmethod
    async def validate_sendgrid_key(session, key: str) -> dict:
        """Active Validation: SendGrid GET /v3/scopes (read-only)."""
        try:
            headers = {"Authorization": f"Bearer {key}"}
            async with session.get("https://api.sendgrid.com/v3/scopes", headers=headers, timeout=8) as response:
                if response.status == 200:
                    data = await response.json()
                    scopes = data.get("scopes", [])
                    return {
                        "valid": True,
                        "scopes_count": len(scopes),
                        "has_send": "mail.send" in scopes
                    }
        except Exception:
            pass
        return {"valid": False}
