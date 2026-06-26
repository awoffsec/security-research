import os, requests, re, time, datetime

USERNAME = os.environ["GH_USERNAME"]
TOKEN = os.environ["GH_TOKEN"]
headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
}

# --- Fetch advisories ---
found = []
page = 1
session = requests.Session()
session.headers.update(headers)

while True:
    resp = session.get(f"https://api.github.com/advisories?per_page=100&page={page}")
    if resp.status_code == 403:
        print("Rate limited, sleeping...")
        time.sleep(60)
        continue
    data = resp.json()
    if not data or not isinstance(data, list):
        break
    print(f"Page {page} fetched — {len(data)} advisories")
    for adv in data:
        for credit in (adv.get("credits") or []):
            user = credit.get("user")
            if user and user.get("login", "").lower() == USERNAME.lower():
                found.append({
                    "ghsa_id": adv["ghsa_id"],
                    "cve_id": adv.get("cve_id") or "N/A",
                    "summary": adv["summary"],
                    "severity": adv.get("severity", "unknown").capitalize(),
                    "credit_type": credit.get("type", "finder").capitalize(),
                    "url": adv["html_url"],
                    "published": adv.get("published_at", "")[:10],
                })
    page += 1
    time.sleep(0.1)

print(f"Found {len(found)} advisories for {USERNAME}.")

# --- Build markdown table ---
if found:
    rows = "\n".join(
        f"| [{a['ghsa_id']}]({a['url']}) | {a['cve_id']} | {a['summary'][:60]} | {a['severity']} | {a['credit_type']} | {a['published']} |"
        for a in sorted(found, key=lambda x: x["published"], reverse=True)
    )
    table = f"""## Security Advisories

> Auto-updated daily. Advisories from the [GitHub Advisory Database](https://github.com/advisories) where I am credited.

| Advisory | CVE | Summary | Severity | Role | Published |
|----------|-----|---------|----------|------|-----------|
{rows}

*Last updated: {datetime.date.today()}*
"""
else:
    table = f"""## 🔐 Security Advisories

> Auto-updated daily. No credited advisories found yet.

*Last updated: {datetime.date.today()}*
"""

# --- Update README between markers ---
with open("README.md", "r") as f:
    readme = f.read()

updated = re.sub(
    r"<!-- ADVISORIES:START -->.*<!-- ADVISORIES:END -->",
    f"<!-- ADVISORIES:START -->\n{table}\n<!-- ADVISORIES:END -->",
    readme,
    flags=re.DOTALL
)

with open("README.md", "w") as f:
    f.write(updated)

print("README.md updated successfully.")
