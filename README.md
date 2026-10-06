# BrandGuard - Digital Risk Protection: Social & App Monitoring

Zero-dependency prototype (Python 3.9+ standard library, SQLite, vanilla JS).

## Run
```
python app.py          # http://localhost:8000
python test_detection.py
```
1. **Brand profile**: click "Load Acme Bank demo" (or enter your own, upload a logo) and save.
2. **Scan and findings**: run a scan. Official accounts/apps are skipped, impersonators are ranked with reasons. TikTok is
   deliberately "unavailable" to show graceful degradation.
3. **Quick name check**: try `Acme  Bank`, `Acm3 B@nk`, `Acme Bnak`, `Acme Bank Support`, `Acme Bakery`.

## Files
| File | Purpose |
|---|---|
| `app.py` | HTTP server + JSON API |
| `brand_profile.py` | profile validation (handles, domains, app ids, logo fingerprint) |
| `connectors.py` | data sources; sample feeds now, real APIs later |
| `detection.py` | look-alike names, logo, content, publisher scoring, official exclusion |
| `storage.py` | SQLite persistence |
| `static/index.html` | UI |
| `data/` | demo brand and sample social/app feeds |
| `ARCHITECTURE.md` | architecture diagram |

## Going live
Replace `FileSource.fetch` in `connectors.py` with a platform API, scraper or threat-intel vendor feed that returns the same
fields (`name, handle/app_id, bio/description, link, followers, verified, created_days, developer, logo_hash`). The logo
fingerprint is an 8x8 average hash computed in the browser, and live connectors should hash candidate avatars the same way.
