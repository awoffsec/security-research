import os, re, datetime, requests

USERNAME = os.environ["GH_USERNAME"]
TOKEN = os.environ["GH_TOKEN"]

headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
}

found = []
page = 1

while True:
    print(f"Fetching page {page}...", flush=True)
    resp = requests.get(
        f"https://api.github.com/advisories?per_page=100&page={page}",
        headers=headers
    )
    data = resp.json()

    if not data or not isinstance(data, list) or len(data) == 0:
        print("No more data, stopping.", flush=True)
        break

    for adv in data:
        for credit in (adv.get("credits") or []):
            user = credit.get("user")
            if user and user.get("login", "").lower() == USERNAME.lower():
                cve = next(
                    (i["value"] for i in adv.get("identifiers", []) if i["type"] == "CVE"),
                    "N/A"
                )
                found.append({
                    "ghsa_id": adv["ghsa_id"],
                    "cve_id": cve,
                    "summary": adv["summary"],
                    "severity": (adv.get("severity") or "unknown").capitalize(),
                    "url": adv["html_url"],
                    "published": (adv.get("published_at") or "")[:10],
                })
                print(f"  ✓ Match found: {adv['ghsa_id']}", flush=True)

    page += 1

print(f"Done. Found {len(found)} advisories for {USERNAME}.", flush=True)
