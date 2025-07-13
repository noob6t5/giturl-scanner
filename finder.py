import os
import re
import requests
import subprocess
import concurrent.futures
import shutil
import socket
import dns.resolver
from git import Repo
from urllib.parse import urlparse
from bs4 import BeautifulSoup

GITHUB_API = "https://api.github.com"
GITHUB_TOKEN = os.getenv("GH_TOKEN")

HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
    "User-Agent": "blackhat-recon"
}

EXTENSIONS_TO_SCAN = [
    ".md", ".py", ".js", ".yml", ".yaml", ".json", ".rb", ".go",
    ".ts", ".sh", ".txt", ".html", ".css", ".env", ".ini", ".cfg"
]

URL_REGEX = re.compile(
    r"https?://[a-zA-Z0-9.-]+\.[a-z]{2,6}(?::\d+)?(?:/[^\s<>{}\\[\\]|\\^`\"']*)?",
    re.IGNORECASE
)

FUZZABLE_URL_RE = re.compile(r"https?://[^\s]+[=/?&]{1}[^\s]*", re.IGNORECASE)

PACKAGE_REGEXES = {
    "npm": re.compile(r'"(@?[a-zA-Z0-9_\-/]+)"\s*:\s*"[\^~]?[\d\.]+"'),
    "pypi": re.compile(r'(?i)^\s*([a-zA-Z][a-zA-Z0-9_\-]*)\s*(?:[=<>!~]+[\d\.\*]+)?', re.MULTILINE),
    "gem": re.compile(r'gem\s+["\']([a-zA-Z0-9_\-]+)["\']'),
    "go": re.compile(r'(?m)^require\s+(?:\()?([\w\-./]+)[\s]+v?[\d\.]+')
}

PACKAGE_REGISTRIES = {
    "npm": lambda name: f"https://registry.npmjs.org/{name}",
    "pypi": lambda name: f"https://pypi.org/pypi/{name}/json",
    "gem": lambda name: f"https://rubygems.org/gems/{name}",
    "go": lambda name: f"https://pkg.go.dev/{name}",
}

def dns_resolves(host):
    try:
        dns.resolver.resolve(host, "A")
        return True
    except:
        return False

def is_valid_url(url):
    parsed = urlparse(url)
    host = parsed.hostname or ""

    if not host or any(
        host.startswith(prefix)
        for prefix in ["127.", "0.", "10.", "192.168.", "169.254."] + [f"172.{i}." for i in range(16, 32)]
    ):
        return False

    if host.endswith((".example", ".test", ".invalid", ".localhost", ".foo", ".bar")):
        return False

    if any(bad in url.lower() for bad in ["{", "}", "%", "xn--", "/commit/", "/issues/", ".com:/"]):
        return False

    try:
        socket.inet_aton(host)
        return False
    except:
        pass

    try:
        if not dns_resolves(host):
            return False
    except:
        return False

    return True

def check_package_url(name, lang):
    name = name.strip()

    ban_list = {
        "host", "port", "design", "pretty", "performance", "value", "index", "main", "default",
        "debug", "error", "message", "json", "config", "release", "object", "input", "output",
        "none", "true", "false", "null"
    }

    if (
        not name or len(name) < 2 or
        name.lower() in ban_list or
        name.strip().isdigit() or
        re.fullmatch(r"[-_.]+", name) or
        re.match(r"^[A-Z0-9_]{3,}$", name) or
        re.search(r"[^a-zA-Z0-9_\-]", name) or
        name.startswith("-") or
        name.endswith("-") or
        name.count("-") > 3
    ):
        return name, "INVALID"

    url = PACKAGE_REGISTRIES[lang](name)
    try:
        r = requests.get(url, timeout=6)
        if r.status_code == 200:
            return name, "Exists"
        elif r.status_code == 404:
            return name, "POTENTIALLY HIJACKABLE"
        else:
            return name, f"Error {r.status_code}"
    except:
        return name, "Request Failed"

def check_github_hijack(pkg_name):
    match = re.search(r"(?:github\.com/)([\w\-]+)/([\w\-]+)", pkg_name)
    if not match:
        return None, None
    owner, repo = match.groups()
    url = f"{GITHUB_API}/repos/{owner}/{repo}"
    try:
        res = requests.get(url, headers=HEADERS, timeout=5)
        if res.status_code == 404:
            return f"https://github.com/{owner}/{repo}", "POTENTIAL HIJACK"
        elif res.status_code == 200:
            return f"https://github.com/{owner}/{repo}", "Exists"
        else:
            return f"https://github.com/{owner}/{repo}", f"Error {res.status_code}"
    except Exception:
        return f"https://github.com/{owner}/{repo}", "Request Failed"

def get_repos(org):
    repos = []
    page = 1
    while True:
        url = f"{GITHUB_API}/orgs/{org}/repos?per_page=100&page={page}"
        res = requests.get(url, headers=HEADERS)
        if res.status_code != 200:
            raise Exception(f"GitHub API error: {res.text}")
        data = res.json()
        if not data:
            break
        for repo in data:
            repos.append(repo['clone_url'])
        page += 1
    return repos

def clone_repo(clone_url, dest_dir):
    if os.path.exists(dest_dir):
        try:
            _ = Repo(dest_dir).git_dir
            print(f"[!] Skipping (already cloned): {clone_url}")
            return
        except:
            print(f"[!] Detected dir but no repo, recloning: {clone_url}")
            shutil.rmtree(dest_dir)
    try:
        Repo.clone_from(clone_url, dest_dir)
        print(f"[+] Cloned: {clone_url}")
    except Exception as e:
        print(f"[!] Failed to clone {clone_url}: {e}")

def normalize_package_matches(matches):
    return [x[0] if isinstance(x, tuple) else x for x in matches if isinstance(x, (tuple, str)) and len(x)]

def extract_urls_and_packages(repo_path):
    findings = {"urls": set(), "packages": {k: set() for k in PACKAGE_REGEXES.keys()}}
    for root, dirs, files in os.walk(repo_path):
        for f in files:
            ext = os.path.splitext(f)[1]
            if ext.lower() in EXTENSIONS_TO_SCAN:
                full_path = os.path.join(root, f)
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as file:
                        content = file.read()
                        urls = filter(is_valid_url, URL_REGEX.findall(content))
                        findings["urls"].update(urls)
                        fuzzables = filter(is_valid_url, FUZZABLE_URL_RE.findall(content))
                        findings["urls"].update(fuzzables)
                        for lang, regex in PACKAGE_REGEXES.items():
                            matches = regex.findall(content)
                            findings["packages"][lang].update(normalize_package_matches(matches))
                except Exception as e:
                    print(f"[!] Error reading {full_path}: {e}")
    return findings

def write_output(org, findings):
    os.makedirs("output", exist_ok=True)
    with open(f"output/{org}_recon.txt", "w") as f:
        f.write("==== VALID URLs ====\n")
        for url in sorted(findings["urls"]):
            f.write(f"{url}\n")

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            for lang, pkgs in findings["packages"].items():
                f.write(f"\n==== {lang.upper()} Packages (Status) ====\n")
                futures = [executor.submit(check_package_url, p, lang) for p in pkgs]
                for name, status in [f.result() for f in concurrent.futures.as_completed(futures)]:
                    if status != "INVALID":
                        pkg_url = PACKAGE_REGISTRIES[lang](name)
                        f.write(f"{name} -> {pkg_url} [{status}]\n")

                if lang in ("go", "npm"):
                    f.write(f"\n---- {lang.upper()} GitHub Repo Checks ----\n")
                    for pkg in pkgs:
                        gh_url, gh_status = check_github_hijack(pkg)
                        if gh_url and gh_status == "POTENTIAL HIJACK":
                            f.write(f"{pkg} => {gh_url} [{gh_status}]\n")

def main():
    import sys
    if len(sys.argv) < 2:
        org = input("Enter GitHub Organization: ").strip()
    else:
        org = sys.argv[1].strip()

    org_dir = f"repos_{org}"
    os.makedirs(org_dir, exist_ok=True)

    print(f"[*] Fetching repos for org: {org}")
    repos = get_repos(org)
    master_findings = {"urls": set(), "packages": {k: set() for k in PACKAGE_REGEXES.keys()}}

    for clone_url in repos:
        name = clone_url.split("/")[-1].replace(".git", "")
        dest = os.path.join(org_dir, name)
        clone_repo(clone_url, dest)
        results = extract_urls_and_packages(dest)
        master_findings["urls"].update(results["urls"])
        for k in PACKAGE_REGEXES:
            master_findings["packages"][k].update(results["packages"][k])

    write_output(org, master_findings)
    print(f"[+] Recon complete. Output saved to output/{org}_recon.txt")

if __name__ == "__main__":
    main()

