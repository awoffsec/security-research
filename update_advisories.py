import os, re, time, datetime, requests
from bs4 import BeautifulSoup

USERNAME = os.environ["GH_USERNAME"]
TOKEN = os.environ["GH_TOKEN"]

session = requests.Session()
session.headers.update({
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "text/html",
    "User-Agent": "Mozilla/5.0"
})

# --- Scrape GitHub advisory credit pages ---
found = []
page = 1

while True:
    url = f"https://github.com/advisories?query=credit%3A{USERNAME}&page={page}"
    resp = session.get(url)
    print(f"Page {page} — status {resp.status_code}")

    soup = BeautifulSoup(resp.text, "html.parser")
    advisories = soup.select("div.Box-row")

    if not advisories:
        break

    for adv in advisories:
        # GHSA link
        link = adv.select_one("a[href*='/advisories/GHSA']")
        if not link:
            continue
        href = link["href"]
        ghsa_id = href.split("/")[-1]
        advisory_url = f"https://github.com{href}"

        # Summary
        summary = link.get_text(strip=True)

        # Severity
        severity_el = adv.select_one("span.Label")
        severity = severity_el.get_text(strip=True) if severity_el else "Unknown"

        # CVE
        cve_el = adv.find(string=re.compile(r"CVE-\d{4}-\d+"))
        cve_id = cve_el.strip() if cve_el else "N/A"

        # Published date
        date_el = adv.select_one("relative-time")
        published = date_el["datetime"][:10] if date_el else "N/A"

        found.append({
            "ghsa_id": ghsa_id,
            "cve_id": cve_id,
            "summary": summary,
            "severity": severity,
            "url": advisory_url,
            "published": published,
        })

    page += 1
    time.sleep(0.5)

print(f"Found {len(found)} advisories for {USERNAME}.")

# --- Build markdown table ---
if found:
    rows = "\n".join(
        f"| [{a['ghsa_id']}]({a['url']}) | {a['cve_id']} | {a['summary'][:60]} | {a['severity']} | {a['published']} |"
        for a in sorted(found, key=lambda x: x["published"], reverse=True)
    )
    table = f"""## Security Advisories

> Auto-updated daily. Advisories from the [GitHub Advisory Database](https://github.com/advisories) where I am credited.

| Advisory | CVE | Summary | Severity | Published |
|----------|-----|---------|----------|-----------|
{rows}

*Last updated: {datetime.date.today()}*
"""
else:
    table = f"""## Security Advisories

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
