import re
from urllib.parse import urlparse


NOT2SAVE_DOMAINS = {
    "example",
    "example.com",
    "example.org",
    "example.net",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "test.com",
    "dummy.com",
    "youtube.com",
    "stackoverflow.com",
    "bitly.com",
    "en.wikipedia.org" ,
    "apache.org/licenses"
}
# can be added more further
def normalize_hostname(hostname):
    if not hostname:
        return ""
    return hostname.lower().lstrip("www.")


def is_validurl(url: str) -> bool:
    try:
        parsed = urlparse(url)
        hostname = normalize_hostname(parsed.hostname)
        if not hostname:
            return False
        if hostname in NOT2SAVE_DOMAINS:
            return False
        if re.search(r"\{\{.*?\}\}", url) or "{" in url or "}" in url:
            return False
        if re.match(
            r"https?://[^/]+\.\w{1,6}[:/]*$", url
        ):  # overly short root or malformed
            return False
    except:
        return False
    return True

# for false-positive package names
NOT2SAVE_PACKAGES = {
    "host",
    "port",
    "design",
    "pretty",
    "performance",
    "value",
    "index",
    "main",
    "default",
    "debug",
    "error",
    "message",
    "json",
    "config",
    "release",
    "object",
    "input",
    "output",
    "none",
    "true",
    "false",
    "null",
    "env",
    "test",
    "data",
    "code",
    "temp",
    "sample",
}


def is_valid_package(pkg: str) -> bool:
    if not pkg or len(pkg.strip()) < 2:
        return False
    if pkg.lower() in NOT2SAVE_PACKAGES:
        return False
    if pkg.isdigit() or re.fullmatch(r"[-_.]+", pkg):
        return False
    if re.match(r"^[A-Z0-9_]{3,}$", pkg):
        return False
    if re.search(r"[^a-zA-Z0-9_\-\.]", pkg):  # Allow dots for Java/Maven style
        return False
    return True
