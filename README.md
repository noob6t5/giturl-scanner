# giturl-scanner
This tool goes through all public (non-archived) repos of any GitHub org, clones them, extracts every URL and package dependency. 
Inspired by similar tool of **Arshad Kazmi** [github-scanner-local](https://github.com/arshadkazmi42/github-scanner-local)

---

## ⚡ What It Does

- 🔎 Clones all **non-archived** repos from a GitHub org using api
- 🕵️ Extracts **URLs** from code, docs, configs, HTML, JSON, etc.
- ⚔️ Validates URLs using [`httpx`](https://github.com/projectdiscovery/httpx)
- 📦 Extracts packages (npm, pypi, gem, go)
- 💀 Flags **broken links** + **potentially hijackable packages**

---

## 🛠 Requirements
- Python 3.x

- httpx Go tool in your $PATH

- Optional: GH_TOKEN set for higher GitHub API limits
## 🚀 Usage

```bash
export GH_TOKEN=gh_yourtoken

git clone https://github.com/noob6t5/giturl-scanner.git

cd giturl-scanner

python3 finder.py <github-org-name>
```
---
## TODO
- [ ] Scan secrets in cloned repo using TruffleHog and Gitleaks
- [ ] Add `requirements.txt`
- [ ] Adjust exporting GitHub token safely
- [ ] Add total repo counter and Clone silently to avoid terminal flooding
- [ ] Configure with [Confused](https://github.com/visma-prodsec/confused) for dependency confusion
- [ ] Add -f for folder of repos
