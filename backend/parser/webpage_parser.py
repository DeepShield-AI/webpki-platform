
import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# 常见公共域名（可扩展）
COMMON_DOMAINS = {
    'google.com',
    'googleapis.com',
    'google-analytics.com',
    'googletagmanager.com',
    'googleads.g.doubleclick.net',
    'gstatic.com',
    
    'cloudflare.com',
    'cloudflareinsights.com',

    'youtube.com',
    'facebook.com',
    'facebook.net',
    'twitter.com'
    
    'instagram.com',
    'github.com',
    'i.ytimg.com',
    
    # 'cdn.jsdelivr.net',
    # 'use.fontawesome.com',
    # 'code.jquery.com',
    # 'static.xx.fbcdn.net',
    # 'player.vimeo.com',
    # 'tags.tiqcdn.com'
    
    'schema.org',
    'www.w3.org'
}

def extract_domains_from_response(dest, response):
    """
    从 requests.Response 对象中解析出页面中的所有域名（排除常见公共域名）
    """
    domains = set()
    
    try:
        soup = BeautifulSoup(response.text, 'html.parser')

        # 提取常见属性中的 URL
        attrs = ['href', 'src', 'data-src', 'action', 'srcset']
        for tag in soup.find_all(True):
            for attr in attrs:
                val = tag.get(attr)
                if val:
                    parts = val.split(',') if attr == 'srcset' else [val]
                    for part in parts:
                        url_match = re.search(r'https?://[^\s"\'<>]+', part)
                        if url_match:
                            hostname = urlparse(url_match.group()).hostname
                            if hostname:
                                domains.add(hostname.lower())

        # 额外从页面正文抓域名
        raw_urls = re.findall(r'https?://([a-zA-Z0-9.-]+)', response.text)
        for host in raw_urls:
            domains.add(host.lower())

        # 移除常见公共域名
        domains.difference_update(COMMON_DOMAINS)
        domains = {d for d in domains if not any(d == root or d.endswith(f".{root}") for root in COMMON_DOMAINS)}

        # 移除自身
        domains.remove(dest)

    except Exception as e:
        print(f"[!] Failed to parse: {e}")

    return sorted(domains)

if __name__ == "__main__":
    dest = 'https://www.ey.gov.tw'
    resp = requests.get(dest)
    domains = extract_domains_from_response(dest, resp)
    print(domains)
