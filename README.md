# Site Inspector


> Passive-first website recon and security-hygiene checker with optional active checks. **Use only with permission.**


## Quickstart (Local)


```bash
# 1) Clone
git clone https://github.com/<your-username>/site-inspector.git
cd site-inspector


# 2) Python env
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt


# 3) Configure
cp .env.example .env
# edit .env to enable optional checks if you understand the risk


# 4) Run Web UI
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
# open http://localhost:8000


# 5) CLI
python cli.py https://example.com -o report.json
