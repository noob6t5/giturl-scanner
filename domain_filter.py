import re
from urllib.parse import urlparse

# Skip useless domains
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
    "en.wikipedia.org",
    "apache.org/licenses",
    "avatars.githubusercontent.com",
    "www.w3.org",
}
# TODO: Add from CLI too

def normalize_hostname(hostname):
    if not hostname:
        return ""
    return hostname.lower().lstrip("www.")


def is_validurl(url: str) -> bool:
    try:
        parsed = urlparse(url)
        hostname = normalize_hostname(parsed.hostname)
        path = parsed.path.lower()

        if not hostname:
            return False

        if hostname in NOT2SAVE_DOMAINS:
            return False

        if re.search(r"\{\{.*?\}\}", url) or "{" in url or "}" in url:
            return False

        if re.match(r"https?://[^/]+\.\w{1,6}[:/]*$", url):
            return False  

        # ===== GitHub-specific filtering =====
        if hostname == "github.com":
            # Block  PRs, issues, etc
            if re.search(
                r"/(pull|issues|commit|commits|discussions|blob|tree|compare|releases|actions)(/|$)",
                path,
            ):
                return False

        # Block GitHub actions or PR trash if somehow missed
        if (
            "/pull/" in path
            or "/issues/" in path
            or "/commit/" in path
            or "/discussions/" in path
        ):
            return False

        # Still allow:
        # - https://github.com/user
        # - https://github.com/user/repo
        # - https://raw.githubusercontent.com/...
        # - https://gist.github.com/...

    except:
        return False

    return True


# Common non-target packages (false-positive filter)
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
    if re.search(r"[^a-zA-Z0-9_\-\.]", pkg):  # allow dot for Maven style
        return False
    return True
