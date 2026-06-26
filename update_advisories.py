import os, requests, re

USERNAME = os.environ["GH_USERNAME"]
TOKEN = os.environ["GH_TOKEN"]
headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
}

found = []
page = 1
while True:
    resp = requests.get(
        f"https://api.github.com/advisories?per_page=100&page={page}",
        headers=headers
    )
    data = resp.json()
    if not data:
        break
    for adv in data:
        for credit in (adv.get("credits") or []):
            if credit.get("user", {}).get("login", "").lower() == USERNAME.lower():
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

# Build markdown table
rows = "\n".join(
    f"| [{a['ghsa_id']}]({a['url']}) | {a['cve_id']} | {a['summary'][:60]}... | {a['severity']} | {a['credit_type']} | {a['published']} |"
    for a in sorted(found, key=lambda x: x["published"], reverse=True)
)

table = f"""## Security Advisories

> Auto-updated daily. Advisories from the [GitHub Advisory Database](https://github.com/advisories) where I am credited.

| Advisory | CVE | Summary | Severity | Role | Published |
|----------|-----|---------|----------|------|-----------|
{rows}

*Last updated: {__import__('datetime').date.today()}*
"""

# Replace section in README between markers
readme = open("README.md").read()
updated = re.sub(
    r"<!-- ADVISORIES:START -->.*<!-- ADVISORIES:END -->",
    f"<!-- ADVISORIES:START -->\n{table}\n<!-- ADVISORIES:END -->",
    readme,
    flags=re.DOTALL
)
open("README.md", "w").write(updated)
print(f"Found {len(found)} advisories.")
