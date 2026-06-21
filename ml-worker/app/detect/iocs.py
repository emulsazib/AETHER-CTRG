"""Real IoC extraction — regex over the artifact's actual content.

Extracts IPv4s, domains, URLs, email addresses, file hashes, Windows registry
keys and suspicious file paths, then defangs network indicators for safe output.
"""
from __future__ import annotations

import re
from typing import Dict, List

from .utils import safe_defang

_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_URL = re.compile(r"\b(?:https?|ftp)://[^\s'\"<>)\]]{4,200}", re.I)
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,18}\b", re.I)
_EMAIL = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.I)
_MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.I)
_SHA1 = re.compile(r"\b[a-f0-9]{40}\b", re.I)
_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I)
_REGKEY = re.compile(r"\bHK(?:LM|CU|EY_[A-Z_]+)\\[\\A-Za-z0-9 _.-]{3,120}", re.I)
_WINPATH = re.compile(r"\b[A-Za-z]:\\[\\A-Za-z0-9 _.$-]{2,120}\.[A-Za-z0-9]{1,5}\b")

# Noise domains we never want to report as IoCs.
_DOMAIN_DENYLIST = {
    "w3.org", "schemas.microsoft.com", "example.com", "example.org",
    "purl.org", "adobe.com", "ns.adobe.com", "iptc.org", "xmlns.com",
}
_TLD_OK = re.compile(r"\.(com|net|org|io|ru|cn|xyz|top|info|biz|stream|cc|su|gq|tk|ml|pw|club|online|site|shop|live|app|dev|co|us|uk|de|fr|nl|in|br|win|loan|click|download|zip|mov)$", re.I)


def extract_iocs(text: str) -> Dict[str, List[str]]:
    urls = sorted(set(_URL.findall(text)))[:60]
    ips = sorted(set(_IPV4.findall(text)))[:60]

    domains = []
    seen = set()
    for d in _DOMAIN.findall(text):
        dl = d.lower()
        if dl in _DOMAIN_DENYLIST or dl in seen:
            continue
        if not _TLD_OK.search(dl):
            continue
        if _IPV4.fullmatch(d):
            continue
        seen.add(dl)
        domains.append(d)
    domains = domains[:60]

    hashes = sorted(set(_SHA256.findall(text)) | set(_SHA1.findall(text)) | set(_MD5.findall(text)))[:40]
    emails = sorted(set(_EMAIL.findall(text)))[:30]
    regkeys = sorted(set(_REGKEY.findall(text)))[:30]
    paths = sorted(set(_WINPATH.findall(text)))[:30]

    # Defanged, de-duplicated flat list for the UI / OpenCTI push.
    flat: List[str] = []
    flat += [safe_defang(u) for u in urls]
    flat += [safe_defang(i) for i in ips]
    flat += [safe_defang(d) for d in domains]
    flat += hashes
    seen_flat = set()
    flat = [x for x in flat if not (x in seen_flat or seen_flat.add(x))]

    return {
        "flat": flat[:120],
        "urls": urls, "ips": ips, "domains": domains,
        "hashes": hashes, "emails": emails,
        "registry_keys": regkeys, "file_paths": paths,
    }
