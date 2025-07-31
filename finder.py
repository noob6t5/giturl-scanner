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
from domain_filter import is_validurl, is_valid_package


GITHUB_API = "https://api.github.com"
GITHUB_TOKEN = os.getenv("GH_TOKEN")

HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
    "User-Agent": "gh-recon",
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
    ".htm",
    ".css",
    ".env",
    ".ini",
    ".cfg",
]

URL_REGEX = re.compile(r"https?://[^\s\"\'<>\\)]+", re.IGNORECASE)

PACKAGE_REGISTRIES = {
    "npm": lambda name: f"https://registry.npmjs.org/{name}",
    "pypi": lambda name: f"https://pypi.org/pypi/{name}/json",
    "gem": lambda name: f"https://rubygems.org/gems/{name}",
    "go": lambda name: f"https://pkg.go.dev/{name}",
}


def check_package_url(name, lang):
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


def check_url_live(url):
    try:
        res = requests.get(url, timeout=5)
        if res.status_code < 400:
            return url, True
        else:
            return url, False
    except:
        return url, False


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
                packages["pypi"].update(data.get("packages", {}).keys())
                packages["pypi"].update(data.get("dev-packages", {}).keys())
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


def extract_urls_and_packages(repo_path):
    findings = {
        "urls": set(),
        "packages": {k: set() for k in PACKAGE_REGISTRIES.keys()},
    }
    for root, dirs, files in os.walk(repo_path):
        for f in files:
            full_path = os.path.join(root, f)
            ext = os.path.splitext(f)[1].lower()
            if ext in EXTENSIONS_TO_SCAN:
                try:
                    with open(
                        full_path, "r", encoding="utf-8", errors="ignore"
                    ) as file:
                        content = file.read()
                        raw_urls = URL_REGEX.findall(content)
                        if full_path.endswith(".md"):
                            raw_urls += re.findall(
                                r"\[.*?\]\((https?://[^\s\)]+)\)", content
                            )
                        if full_path.endswith((".html", ".htm")):
                            soup = BeautifulSoup(content, "html.parser")
                            raw_urls += [
                                a["href"]
                                for a in soup.find_all("a", href=True)
                                if a["href"].startswith("http")
                            ]
                        if full_path.endswith(".json"):
                            content = content.replace("\\/", "/")
                        if raw_urls:
                            print(f"[+] Found {len(raw_urls)} URLs in {full_path}")
                            for u in raw_urls:
                                print(f"    URL: {u}")
                            filtered = [u for u in raw_urls if  is_validurl(u)]
                            findings["urls"].update(filtered)
                        declared = extract_declared_packages(full_path)
                        for k in declared:
                            cleaned = {p for p in declared[k] if is_valid_package(p)}
                            findings["packages"][k].update(cleaned)
                except Exception as e:
                    print(f"[!] Error reading {full_path}: {e}")
    return findings
# org from here
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


def write_output(org, findings):
    os.makedirs("output", exist_ok=True)
    with open(f"output/{org}_recon.txt", "w") as f:
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            f.write("==== Live URLs (via requests) ====\n")
            live_urls, dead_urls = [], []
            futures = [executor.submit(check_url_live, url) for url in findings["urls"]]
            for future in concurrent.futures.as_completed(futures):
                url, is_live = future.result()
                if is_live:
                    live_urls.append(url)
                    f.write(f"{url}\n")
                else:
                    dead_urls.append(url)

            f.write("\n==== Broken URLs (via requests) ====\n")
            for url in dead_urls:
                f.write(f"{url}\n")

            for lang, pkgs in findings["packages"].items():
                f.write(f"\n==== {lang.upper()} Packages (Status) ====\n")
                pkg_futures = [
                    executor.submit(check_package_url, p, lang)
                    for p in pkgs
                    if is_valid_package(p)
                ]
                for pf in concurrent.futures.as_completed(pkg_futures):
                    name, status = pf.result()
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

    try:
        for clone_url in repos:
            name = clone_url.split("/")[-1].replace(".git", "")
            dest = os.path.join(org_dir, name)
            clone_repo(clone_url, dest)
            results = extract_urls_and_packages(dest)
            master_findings["urls"].update(results["urls"])
            for k in PACKAGE_REGISTRIES:
                master_findings["packages"][k].update(results["packages"][k])
            write_output(org, master_findings)
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Saving partial results...")
    finally:
        write_output(org, master_findings)
        print(f"[+] Output saved to output/{org}_recon.txt")


if __name__ == "__main__":
    main()
