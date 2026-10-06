"""Brand profile validation + normalization. Returns (clean_profile, errors, warnings)."""
import re
from detection import skeleton, norm_handle

PLATFORMS = {'instagram', 'x', 'facebook', 'linkedin', 'tiktok', 'youtube'}
STORES = {'play', 'appstore'}
DOMAIN = re.compile(r'^[a-z0-9-]+(\.[a-z0-9-]+)+$')


def _list(v):
    return [str(x).strip() for x in (v or []) if str(x).strip()]


def validate(p):
    errors, warnings = [], []
    c = {'name': str(p.get('name', '')).strip()}
    if not c['name']: errors.append('Brand name is required.')
    elif len(c['name']) > 80: errors.append('Brand name must be 80 characters or fewer.')
    elif len(skeleton(c['name'])) < 4: warnings.append('Very short brand names cause more false matches; add aliases or an allow-list.')
    c['aliases'] = list(dict.fromkeys(_list(p.get('aliases'))))
    c['benign_names'] = list(dict.fromkeys(_list(p.get('benign_names'))))
    c['domains'] = []
    for d in _list(p.get('domains')):
        d = re.sub(r'^https?://', '', d.lower()).split('/')[0].removeprefix('www.')
        if DOMAIN.match(d): c['domains'].append(d)
        else: errors.append(f'"{d}" is not a valid domain.')
    c['official_social'] = []
    for a in p.get('official_social') or []:
        plat, h = str(a.get('platform', '')).strip().lower(), norm_handle(a.get('handle'))
        if plat not in PLATFORMS: errors.append(f'Unknown platform "{plat}". Use: {", ".join(sorted(PLATFORMS))}.')
        elif not re.match(r'^[\w.\-]{2,60}$', h): errors.append(f'Invalid {plat} handle "{a.get("handle")}".')
        else: c['official_social'].append({'platform': plat, 'handle': h})
    c['official_apps'] = []
    for a in p.get('official_apps') or []:
        store, aid = str(a.get('store', '')).strip().lower(), str(a.get('app_id', '')).strip()
        if store not in STORES: errors.append(f'Unknown store "{store}". Use play or appstore.')
        elif not aid: errors.append('Each official app needs an app id (package name or App Store id).')
        else: c['official_apps'].append({'store': store, 'app_id': aid, 'name': str(a.get('name', '')).strip(),
                                         'developer': str(a.get('developer', '')).strip(), 'description': str(a.get('description', '')).strip()})
    devs = _list(p.get('official_developers')) + [a['developer'] for a in c['official_apps'] if a['developer']]
    c['official_developers'] = list(dict.fromkeys(devs))
    lh = str(p.get('logo_hash', '')).strip().lower()
    if lh and not re.match(r'^[0-9a-f]{16}$', lh): errors.append('Logo fingerprint must be 16 hex characters (upload the logo to generate it).')
    c['logo_hash'] = lh
    logo = p.get('logo_data') or ''
    if len(logo) > 1_500_000: errors.append('Logo file is too large (max ~1 MB).'); logo = ''
    c['logo_data'] = logo
    if not c['official_social']: warnings.append('No official social accounts yet: real accounts could be flagged. Add them.')
    if not c['official_apps']: warnings.append('No official apps yet: real apps could be flagged. Add them.')
    if not c['logo_hash']: warnings.append('No logo uploaded: logo-based detection is off.')
    if not c['domains']: warnings.append('No official domains: link checks are off.')
    return c, errors, warnings
