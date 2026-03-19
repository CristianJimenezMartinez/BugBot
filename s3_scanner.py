# -*- coding: utf-8 -*-
import requests

def check_bucket(bucket_name):
    urls = [
        f"https://{bucket_name}.s3.amazonaws.com",
        f"https://{bucket_name}.s3.eu-central-1.amazonaws.com",
        f"https://{bucket_name}.s3.eu-west-1.amazonaws.com"
    ]
    
    print(f"--- Checking Bucket: {bucket_name} ---")
    for url in urls:
        try:
            r = requests.get(url, timeout=5)
            status = r.status_code
            
            if status == 200:
                print(f"[!] VULNERABLE: {url} esta ABIERTO")
            elif "NoSuchBucket" in r.text:
                print(f"[-] TAKEOVER? {url} no existe")
            elif status == 403:
                print(f"[*] PROTEGIDO: {url}")
            else:
                print(f"[?] {url} respondio con estado {status}")
        except:
            pass

targets = [
    "zooplus-assets", "zooplus-static", "zooplus-media",
    "zooplus-images", "zooplus-prod", "zooplus-dev", "zooplus-public"
]

for t in targets:
    check_bucket(t)