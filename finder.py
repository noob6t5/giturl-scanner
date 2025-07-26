import os
import re
import json
import toml
import requests
import shutil
import subprocess
import concurrent.futures
from git import Repo
from urllib.parse import urlparse
from bs4 import BeautifulSoup

GITHUB_API = "https://api.github.com"
GITHUB_TOKEN = os.getenv("GH_TOKEN")

HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
    "User-Agent": "blackhat-recon",
}

EXTENSIONS_TO_SCAN = [
    ".md",
    ".py",
    ".js",
    ".yml",
    ".yaml",
    ".json",
    ".rb",
    ".go",
    ".ts",
    ".sh",
    ".txt",
    ".html",
    ".css",
    ".env",
    ".ini",
    ".cfg",
]

URL_REGEX = re.compile(
    r"https?://[a-zA-Z0-9.-]+\.[a-z]{2,6}(?::\d+)?(?:/[^\s<>{}\\[\\]|\\^`\"']*)?",
    re.IGNORECASE,
)

PACKAGE_REGISTRIES = {
    "npm": lambda name: f"https://registry.npmjs.org/{name}",
    "pypi": lambda name: f"https://pypi.org/pypi/{name}/json",
    "gem": lambda name: f"https://rubygems.org/gems/{name}",
    "go": lambda name: f"https://pkg.go.dev/{name}",
}


def is_valid_url(url):
    parsed = urlparse(url)
    host = parsed.hostname or ""

    dummy_patterns = [
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "example.com",
        "example.org",
        "example.net",
        "foo",
        "bar",
        "test",
        "invalid",
        "localdomain",
        "testserver",
    ]

    if any(dummy in host for dummy in dummy_patterns):
        return False

    bad_netblocks = ["127.", "0.", "10.", "192.168.", "169.254.", "172."]
    if any(host.startswith(prefix) for prefix in bad_netblocks):
        return False

    if "{" in url or "}" in url or "xn--" in host or "%" in url.lower():
        return False

    if "/commit/" in url or "/issues/" in url:
        return False

    if re.search(r"\.com:/", url, re.IGNORECASE):
        return False

    return True


def check_package_url(name, lang):
    name = name.strip()

    ban_list = {
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
    }

    if (
        not name
        or len(name) < 2
        or name.lower() in ban_list
        or name.strip().isdigit()
        or re.fullmatch(r"[-_.]+", name)
        or re.match(r"^[A-Z0-9_]{3,}$", name)
        or re.search(r"[^a-zA-Z0-9_\-]", name)
        or name.startswith("-")
        or name.endswith("-")
        or name.count("-") > 3
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


def extract_declared_packages(file_path):
    packages = {"npm": set(), "pypi": set(), "gem": set(), "go": set()}
    try:
        if file_path.endswith("package.json"):
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                deps = data.get("dependencies", {})
                packages["npm"].update(deps.keys())
        elif file_path.endswith("requirements.txt"):
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip() and not line.startswith("#"):
                        match = re.match(r"([a-zA-Z0-9_\-]+)([=<>!~]+[\d\.\*]+)?", line)
                        if match:
                            packages["pypi"].add(match.group(1))
        elif file_path.endswith("Pipfile"):
            with open(file_path, "r", encoding="utf-8") as f:
                data = toml.load(f)
                default_pkgs = data.get("packages", {})
                dev_pkgs = data.get("dev-packages", {})
                packages["pypi"].update(default_pkgs.keys())
                packages["pypi"].update(dev_pkgs.keys())
        elif file_path.endswith("Gemfile"):
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    match = re.match(r'^\s*gem\s+["\']([a-zA-Z0-9_\-]+)["\']', line)
                    if match:
                        packages["gem"].add(match.group(1))
        elif file_path.endswith("go.mod"):
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    match = re.match(
                        r"\s*require\s+([a-zA-Z0-9_\-./]+)\s+v[\d\.]+", line
                    )
                    if match:
                        packages["go"].add(match.group(1))
    except Exception as e:
        print(f"[!] Failed parsing {file_path}: {e}")
    return packages


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
            if repo.get("archived"):
                print(f"[-] Skipping archived repo: {repo['name']}")
                continue
            repos.append(repo["clone_url"])
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


def extract_urls_and_packages(repo_path):
    findings = {
        "urls": set(),
        "packages": {k: set() for k in PACKAGE_REGISTRIES.keys()},
    }
    for root, dirs, files in os.walk(repo_path):
        for f in files:
            full_path = os.path.join(root, f)
            ext = os.path.splitext(f)[1]
            if ext.lower() in EXTENSIONS_TO_SCAN:
                try:
                    with open(
                        full_path, "r", encoding="utf-8", errors="ignore"
                    ) as file:
                        content = file.read()
                        urls = filter(is_valid_url, URL_REGEX.findall(content))
                        findings["urls"].update(urls)
                except Exception as e:
                    print(f"[!] Error reading {full_path}: {e}")
            declared = extract_declared_packages(full_path)
            for k in declared:
                findings["packages"][k].update(declared[k])
    return findings


def run_httpx(input_file="tmp_urls.txt", output_file="httpx_results.txt"):
    cmd = [
        "httpx",
        "-l",
        input_file,
        "-status-code",
        "-silent",
        "-threads",
        "100",
        "-o",
        output_file,
    ]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def write_output(org, findings):
    os.makedirs("output", exist_ok=True)
    with open(f"output/{org}_recon.txt", "w") as f:

        with open("tmp_urls.txt", "w") as tmp:
            for url in sorted(findings["urls"]):
                tmp.write(url + "\n")

        run_httpx("tmp_urls.txt", "httpx_results.txt")

        broken_links = []
        live_links = []

        with open("httpx_results.txt", "r") as result_file:
            for line in result_file:
                if not line.strip():
                    continue
                try:
                    url, status = re.match(
                        r"(https?://[^\s]+)\s+\[(\d+)\]", line.strip()
                    ).groups()
                    status = int(status)
                    if status >= 400:
                        broken_links.append((url, status))
                    else:
                        live_links.append((url, status))
                except:
                    continue

        f.write("==== Live URLs (via httpx) ====\n")
        for url, code in live_links:
            f.write(f"{url} [HTTP {code}]\n")

        f.write("\n==== Broken URLs (via httpx) ====\n")
        for url, code in broken_links:
            f.write(f"{url} [HTTP {code}] BROKEN\n")

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            for lang, pkgs in findings["packages"].items():
                f.write(f"\n==== {lang.upper()} Packages (Status) ====\n")
                futures = [executor.submit(check_package_url, p, lang) for p in pkgs]
                for future in concurrent.futures.as_completed(futures):
                    name, status = future.result()
                    if status != "INVALID":
                        pkg_url = PACKAGE_REGISTRIES[lang](name)
                        f.write(f"{name} -> {pkg_url} [{status}]\n")


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
    master_findings = {
        "urls": set(),
        "packages": {k: set() for k in PACKAGE_REGISTRIES.keys()},
    }

    for clone_url in repos:
        name = clone_url.split("/")[-1].replace(".git", "")
        dest = os.path.join(org_dir, name)
        clone_repo(clone_url, dest)
        results = extract_urls_and_packages(dest)
        master_findings["urls"].update(results["urls"])
        for k in PACKAGE_REGISTRIES:
            master_findings["packages"][k].update(results["packages"][k])

    write_output(org, master_findings)
    print(f"[+] Recon complete. Output saved to output/{org}_recon.txt")


if __name__ == "__main__":
    main()
