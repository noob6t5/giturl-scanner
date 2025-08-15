import os
import re
import json
import toml
import requests
import shutil
import argparse
import concurrent.futures
from git import Repo
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from domain_filter import is_validurl, is_valid_package

# ========== CONFIG ==========
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
    # i will add other later
}

# Colors
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
C = "\033[96m"
B = "\033[94m"
W = "\033[0m"


# ========== CORE FUNCTIONS ==========
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
        return url, res.status_code < 400
    except:
        return url, False


def extract_declared_packages(file_path):
    packages = {"npm": set(), "pypi": set(), "gem": set(), "go": set()}
    try:
        if file_path.endswith("package.json"):
            data = json.load(open(file_path, encoding="utf-8"))
            packages["npm"].update(data.get("dependencies", {}).keys())
        elif file_path.endswith("requirements.txt"):
            for line in open(file_path, encoding="utf-8"):
                if line.strip() and not line.startswith("#"):
                    m = re.match(r"([a-zA-Z0-9_\-]+)", line)
                    if m:
                        packages["pypi"].add(m.group(1))
        elif file_path.endswith("Pipfile"):
            data = toml.load(open(file_path, encoding="utf-8"))
            packages["pypi"].update(data.get("packages", {}).keys())
            packages["pypi"].update(data.get("dev-packages", {}).keys())
        elif file_path.endswith("Gemfile"):
            for line in open(file_path, encoding="utf-8"):
                m = re.match(r'^\s*gem\s+["\']([a-zA-Z0-9_\-]+)["\']', line)
                if m:
                    packages["gem"].add(m.group(1))
        elif file_path.endswith("go.mod"):
            for line in open(file_path, encoding="utf-8"):
                m = re.match(r"\s*require\s+([a-zA-Z0-9_\-./]+)\s+v", line)
                if m:
                    packages["go"].add(m.group(1))
    except Exception as e:
        print(f"[!] Failed parsing {file_path}: {e}")
    return packages


def extract_urls_and_packages(repo_path):
    findings = {"urls": set(), "packages": {k: set() for k in PACKAGE_REGISTRIES}}
    for root, dirs, files in os.walk(repo_path):
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in EXTENSIONS_TO_SCAN:
                full_path = os.path.join(root, f)
                try:
                    content = open(full_path, encoding="utf-8", errors="ignore").read()
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

                    findings["urls"].update(u for u in raw_urls if is_validurl(u))
                    declared = extract_declared_packages(full_path)
                    for k in declared:
                        findings["packages"][k].update(
                            p for p in declared[k] if is_valid_package(p)
                        )

                except Exception as e:
                    print(f"[!] Error reading {full_path}: {e}")
    return findings


def get_repos(org):
    repos, page = [], 1
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
                continue
            repos.append(repo["clone_url"])
        page += 1
    return repos


def clone_repo(clone_url, dest_dir):
    if os.path.exists(dest_dir):
        try:
            _ = Repo(dest_dir).git_dir
            return
        except:
            shutil.rmtree(dest_dir)
    Repo.clone_from(clone_url, dest_dir)


def write_output(name, findings):
    os.makedirs("output", exist_ok=True)
    filepath = f"output/{name}_recon.txt"
    with open(filepath, "w") as f:
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            f.write("==== Live URLs ====\n")
            live_urls, dead_urls = [], []
            futures = [executor.submit(check_url_live, url) for url in findings["urls"]]
            for future in concurrent.futures.as_completed(futures):
                url, is_live = future.result()
                if is_live:
                    live_urls.append(url)
                    f.write(f"{url}\n")
                else:
                    dead_urls.append(url)

            f.write("\n==== Broken URLs ====\n")
            for url in dead_urls:
                f.write(f"{url}\n")

            for lang, pkgs in findings["packages"].items():
                f.write(f"\n==== {lang.upper()} Packages ====\n")
                pkg_futures = [
                    executor.submit(check_package_url, p, lang) for p in pkgs
                ]
                for pf in concurrent.futures.as_completed(pkg_futures):
                    name_, status = pf.result()
                    if status != "INVALID":
                        pkg_url = PACKAGE_REGISTRIES[lang](name_)
                        f.write(f"{name_} -> {pkg_url} [{status}]\n")
    return filepath


# ========== MAIN ==========
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--org", help="GitHub organization name")
    parser.add_argument("-f", "--folder", help="Local folder with repos")
    parser.add_argument("-s", "--silent", action="store_true", help="Silent mode")
    args = parser.parse_args()

    if not args.org and not args.folder:
        parser.error("Must specify --org or --folder")

    master_findings = {
        "urls": set(),
        "packages": {k: set() for k in PACKAGE_REGISTRIES},
    }

    if args.org:
        repos = get_repos(args.org)
        total = len(repos)
        print(f"{C}[*] Total repos (non-archived): {total}{W}")
        for idx, clone_url in enumerate(repos, 1):
            repo_name = clone_url.split("/")[-1].replace(".git", "")
            if not args.silent:
                print(f"{B}[{idx}/{total}] Scanning: {repo_name}{W}")
            clone_repo(clone_url, f"repos_{args.org}/{repo_name}")
            results = extract_urls_and_packages(f"repos_{args.org}/{repo_name}")
            _merge_findings(master_findings, results, args.silent)
        output_file = write_output(args.org, master_findings)

    elif args.folder:
        repos = [
            os.path.join(args.folder, d)
            for d in os.listdir(args.folder)
            if os.path.isdir(os.path.join(args.folder, d))
        ]
        total = len(repos)
        print(f"{C}[*] Total repos in folder: {total}{W}")
        for idx, repo_path in enumerate(repos, 1):
            repo_name = os.path.basename(repo_path)
            if not args.silent:
                print(f"{B}[{idx}/{total}] Scanning: {repo_name}{W}")
            results = extract_urls_and_packages(repo_path)
            _merge_findings(master_findings, results, args.silent)
        output_file = write_output(os.path.basename(args.folder), master_findings)

    # Final Summary
    print(f"\n{G}===== FINAL SUMMARY ====={W}")
    print(f"Repos scanned: {total}")
    print(f"Total URLs found: {len(master_findings['urls'])}")
    hijack_count = _count_hijackables(master_findings)
    print(f"Total Hijackable Packages: {R}{hijack_count}{W}")
    print(f"Output saved to: {output_file}")


def _merge_findings(master, results, silent):
    for u in results["urls"]:
        master["urls"].add(u)
    for k in PACKAGE_REGISTRIES:
        for p in results["packages"][k]:
            master["packages"][k].add(p)
            # Check hijackable instantly
            name_, status = check_package_url(p, k)
            if status == "POTENTIALLY HIJACKABLE":
                print(
                    f"{R}[!!!] HIJACKABLE ({k.upper()}): {name_} -> {PACKAGE_REGISTRIES[k](name_)}{W}"
                )

def _count_hijackables(findings):
    count = 0
    for k in PACKAGE_REGISTRIES:
        for p in findings["packages"][k]:
            _, status = check_package_url(p, k)
            if status == "POTENTIALLY HIJACKABLE":
                count += 1
    return count
# Would combine confused github tool 

if __name__ == "__main__":
    main()
