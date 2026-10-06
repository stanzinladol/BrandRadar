"""Data-source connectors. Each source returns normalized candidate dicts.
Prototype sources read bundled sample feeds; replace fetch() with a real API/scraper/vendor feed.
A failing source never stops a scan - it is reported as 'unavailable' in the UI."""
import json, os

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


class SourceError(Exception):
    pass


class FileSource:
    def __init__(self, label, kind, platform, filename):
        self.label, self.kind, self.platform, self.filename = label, kind, platform, filename

    def fetch(self, brand):
        # Real connector idea: search the platform for brand name, aliases and lookalike variants.
        path = os.path.join(DATA, self.filename)
        with open(path, encoding='utf-8') as f:
            rows = json.load(f)
        key = 'platform' if self.kind == 'social' else 'store'
        return [{**r, 'kind': self.kind, 'platform': r[key]} for r in rows if r[key] == self.platform]


class UnavailableSource(FileSource):
    def __init__(self, label, kind, platform, reason):
        super().__init__(label, kind, platform, '')
        self.reason = reason

    def fetch(self, brand):
        raise SourceError(self.reason)


SOURCES = [
    FileSource('Instagram', 'social', 'instagram', 'social_feed.json'),
    FileSource('X (Twitter)', 'social', 'x', 'social_feed.json'),
    FileSource('Facebook', 'social', 'facebook', 'social_feed.json'),
    FileSource('LinkedIn', 'social', 'linkedin', 'social_feed.json'),
    UnavailableSource('TikTok', 'social', 'tiktok', 'API credentials not configured or rate limit reached'),
    FileSource('Google Play', 'app', 'play', 'app_feed.json'),
    FileSource('Apple App Store', 'app', 'appstore', 'app_feed.json'),
]


def collect(brand):
    items, statuses = [], []
    for s in SOURCES:
        try:
            got = s.fetch(brand)
            items += got
            statuses.append({'name': s.label, 'kind': s.kind, 'ok': True, 'count': len(got)})
        except Exception as e:  # graceful degradation
            statuses.append({'name': s.label, 'kind': s.kind, 'ok': False, 'count': 0, 'error': str(e)})
    return items, statuses
