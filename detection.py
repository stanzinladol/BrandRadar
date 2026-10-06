"""Detection engine: look-alike names, logo similarity, content/publisher signals.
Pure standard library. Every finding carries human-readable reasons with points."""
import re, unicodedata, difflib
from urllib.parse import urlparse

HOMOGLYPHS = str.maketrans({'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's',
                            '!': 'i', '|': 'l', 'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',
                            'і': 'i', 'ѕ': 's'})
SUSPICIOUS_WORDS = ['support', 'helpdesk', 'help', 'customercare', 'care', 'official', 'verify', 'verification',
                    'secure', 'login', 'signin', 'rewards', 'reward', 'giveaway', 'offers', 'promo', 'bonus',
                    'claim', 'recovery', 'refund', 'kyc', 'wallet', 'loan', 'invest', 'crypto', 'service']
SCAM_PHRASES = ['password', 'verify your account', 'giveaway', 'win ', 'double your money', 'crypto', 'investment',
                'dm us', 'whatsapp', 'otp', 'kyc', 'urgent', 'claim your', 'free money', 'loan approval',
                'call 1-', 'limited offer', 'send us your', 'account suspended']
SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'rb.gy', 'wa.me', 't.me', 'is.gd'}
SEVERITY = [(70, 'high'), (45, 'medium'), (25, 'low')]


def skeleton(s):
    """Lowercase, map look-alike characters (0->o, cyrillic a->a, rn->m), strip accents/punctuation."""
    s = (s or '').lower().translate(HOMOGLYPHS)
    s = unicodedata.normalize('NFKD', s).encode('ascii', 'ignore').decode()
    s = re.sub(r'[^a-z0-9]', '', s)
    return s.replace('rn', 'm').replace('vv', 'w')


def raw_compact(s):
    return re.sub(r'[^a-z0-9]', '', (s or '').lower())


def osa(a, b):
    """Optimal string alignment distance (insert/delete/substitute/adjacent swap)."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1): d[i][0] = i
    for j in range(len(b) + 1): d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            c = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + c)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def _suspicious(leftover):
    return next((w for w in SUSPICIOUS_WORDS if w in leftover), None)


def name_signal(cand, brand_names, benign):
    """Return (points, reason, matched_brand) for one candidate string."""
    cc, rc = skeleton(cand), raw_compact(cand)
    if not cc or cc in benign:
        return 0, '', ''
    best = (0, '', '')
    for b in brand_names:
        bb, rb = skeleton(b), raw_compact(b)
        L = len(bb)
        if rc == rb:
            same = cand.strip().lower() == b.strip().lower()
            r = (45, f'Uses the exact brand name "{b}"') if same else \
                (48, 'Same name with spacing/punctuation changes')
        elif cc == bb:
            r = (50, 'Character substitution (e.g. rn→m, 0→o, look-alike letters)')
        elif L >= 5 and osa(cc, bb) <= (1 if L < 8 else 2):
            r = (42 if osa(cc, bb) == 1 else 36, f'Typo / swapped characters ({osa(cc, bb)} edit from "{b}")')
        elif (L >= 6 and bb in cc) or (L < 6 and (cc.startswith(bb) or cc.endswith(bb))):
            left = cc.replace(bb, '', 1)
            w = _suspicious(left)
            r = (38, f'Brand name plus bait word "{w}"') if w else (18, 'Contains brand name with extra words')
        else:
            r = (0, '')
            if L >= 6:  # misspelled brand + added words, e.g. "Acme Bnak Pay"
                for n in (L - 1, L, L + 1):
                    for i in range(0, len(cc) - n + 1):
                        if osa(cc[i:i + n], bb) <= 1:
                            left = cc[:i] + cc[i + n:]
                            w = _suspicious(left)
                            if w or not left:  # extra non-bait words (e.g. "Acme Bakery") are not flagged
                                r = (40 if w else 34, 'Misspelled brand name' + (f' plus bait word "{w}"' if w else ''))
                                break
                    if r[0]: break
            if not r[0] and L >= 5 and difflib.SequenceMatcher(None, cc, bb).ratio() >= 0.88:
                r = (32, 'Very similar spelling to brand name')
        if r[0] > best[0]:
            best = (r[0], r[1], b)
    return best


def hamming_hex(a, b):
    try:
        return bin(int(a, 16) ^ int(b, 16)).count('1')
    except (TypeError, ValueError):
        return None


def norm_handle(h):
    h = (h or '').strip().lower()
    h = re.sub(r'^https?://[^/]+/', '', h)
    return h.strip('/@ ').split('/')[-1].split('?')[0]


def domain_of(link):
    if not link: return ''
    host = urlparse(link if '//' in link else '//' + link).hostname or ''
    return host[4:] if host.startswith('www.') else host


def is_official(item, brand):
    if item['kind'] == 'social':
        h, p = norm_handle(item.get('handle')), item.get('platform', '').lower()
        return any(a['platform'].lower() == p and norm_handle(a['handle']) == h for a in brand.get('official_social', []))
    ids = {a['app_id'].lower() for a in brand.get('official_apps', [])}
    devs = {raw_compact(d) for d in brand.get('official_developers', [])}
    return item.get('app_id', '').lower() in ids or (raw_compact(item.get('developer')) in devs and raw_compact(item.get('developer')) != '')


def jaccard(a, b):
    wa, wb = set(re.findall(r'[a-z]{3,}', (a or '').lower())), set(re.findall(r'[a-z]{3,}', (b or '').lower()))
    return len(wa & wb) / len(wa | wb) if wa and wb else 0.0


def assess(item, brand):
    """Score one candidate. Returns dict(score, severity, reasons)."""
    names = [n for n in [brand['name']] + brand.get('aliases', []) if len(skeleton(n)) >= 4]
    benign = {skeleton(b) for b in brand.get('benign_names', [])}
    reasons = []
    cands = [item.get('name', ''), item.get('handle', '')]
    nm = max((name_signal(c, names, benign) for c in cands if c), key=lambda t: t[0], default=(0, '', ''))
    name_pts = nm[0]
    if name_pts: reasons.append({'signal': 'name', 'points': name_pts, 'text': nm[1]})

    logo_pts, dist = 0, hamming_hex(item.get('logo_hash'), brand.get('logo_hash'))
    if dist is not None and dist <= 6: logo_pts = 25; txt = f'Logo is a near copy of your official logo (distance {dist}/64)'
    elif dist is not None and dist <= 12: logo_pts = 15; txt = f'Logo is visually similar to your official logo (distance {dist}/64)'
    if logo_pts: reasons.append({'signal': 'logo', 'points': logo_pts, 'text': txt})

    strong = name_pts >= 30 or logo_pts > 0       # primary evidence of impersonation
    weak = name_pts >= 18 or logo_pts > 0         # enough to look at content signals
    text = ' '.join([item.get('bio', ''), item.get('description', ''), item.get('name', '')]).lower()
    hits = [p.strip() for p in SCAM_PHRASES if p in text]
    if weak and hits:
        reasons.append({'signal': 'content', 'points': min(15, 5 * len(hits)), 'text': 'Scam-style wording: ' + ', '.join(f'"{h}"' for h in hits[:3])})
    dom = domain_of(item.get('link'))
    if weak and dom and not any(dom == d or dom.endswith('.' + d) for d in brand.get('domains', [])):
        bb = skeleton(brand['name'])
        if dom in SHORTENERS or bb in skeleton(dom.rsplit('.', 1)[0]):
            reasons.append({'signal': 'link', 'points': 12, 'text': f'Links to {dom}, which is not an official domain' + (' (link shortener)' if dom in SHORTENERS else ' but imitates the brand')})
        else:
            reasons.append({'signal': 'link', 'points': 6, 'text': f'Links to {dom}, which is not an official domain'})
    if item['kind'] == 'app' and weak:
        sim = jaccard(item.get('description'), ' '.join(a.get('description', '') for a in brand.get('official_apps', [])))
        if sim >= 0.3: reasons.append({'signal': 'description', 'points': 10, 'text': f'Description reuses wording from your official app ({int(sim * 100)}% overlap)'})
    if strong:  # corroborating context only counts next to primary evidence
        if item['kind'] == 'app':
            dev = item.get('developer', '')
            dpts = name_signal(dev, names, benign)[0]
            reasons.append({'signal': 'publisher', 'points': 20 if dpts >= 30 else 10,
                            'text': f'Publisher "{dev}" ' + ('imitates your company name' if dpts >= 30 else 'is not one of your official publishers')})
        else:
            if item.get('verified') is False: reasons.append({'signal': 'verified', 'points': 3, 'text': 'Account is not verified'})
            if isinstance(item.get('created_days'), int) and item['created_days'] < 60:
                reasons.append({'signal': 'age', 'points': 5, 'text': f'Created only {item["created_days"]} days ago'})
    score = min(100, sum(r['points'] for r in reasons))
    sev = next((s for t, s in SEVERITY if score >= t), None)
    return {'score': score, 'severity': sev, 'reasons': reasons}


def evaluate(items, brand):
    """Run all candidates through the brand profile. Official assets are excluded first."""
    out, stats = [], {'scanned': len(items), 'excluded_official': 0, 'not_flagged': 0}
    for it in items:
        if is_official(it, brand):
            stats['excluded_official'] += 1; continue
        r = assess(it, brand)
        if not r['severity']:
            stats['not_flagged'] += 1; continue
        out.append({**it, **r})
    out.sort(key=lambda d: -d['score'])
    return out, stats
