import tldextract
from typing import List
from core.cloud.constants import PERMUTATIONS, DELIMITERS, CLOUD_REGIONS

class CloudMutator:
    """Motor atómico para generación de nombres y URLs de buckets."""
    
    @staticmethod
    def generate_names(target: str) -> List[str]:
        """Genera combinaciones lógicas de nombres basándose en el dominio."""
        mutations = set()
        extracted = tldextract.extract(target)
        brand = extracted.domain or target.lower().split('.')[0]
        
        mutations.add(brand)
        for p in PERMUTATIONS:
            for d in DELIMITERS:
                mutations.add(f"{brand}{d}{p}")
                mutations.add(f"{p}{d}{brand}")
                mutations.add(f"{brand}{d}{p}-cdn")
                mutations.add(f"{brand}{d}{p}-assets")
        return list(mutations)

    @staticmethod
    def generate_urls(bucket_name: str) -> List[str]:
        """Genera URLs finales para AWS, GCP y Azure."""
        urls = [
            f"https://{bucket_name}.s3.amazonaws.com",
            f"https://storage.googleapis.com/{bucket_name}",
            f"https://{bucket_name}.blob.core.windows.net/public",
            f"https://{bucket_name}.blob.core.windows.net/assets"
        ]
        for reg in CLOUD_REGIONS:
            urls.append(f"https://{bucket_name}.s3.{reg}.amazonaws.com")
            urls.append(f"https://{bucket_name}.s3-website-{reg}.amazonaws.com")
        return urls
