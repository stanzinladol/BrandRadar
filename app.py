"""BrandGuard - Digital Risk Protection (Social & App Monitoring). Run: python app.py  -> http://localhost:8000"""
import json, os, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import storage, connectors, detection, brand_profile

ROOT = os.path.dirname(os.path.abspath(__file__))


def run_scan():
    brand = storage.get_brand()
    if not brand: raise ValueError('Create a brand profile first.')
    started = time.time() - 0.001
    items, statuses = connectors.collect(brand)
    dets, stats = detection.evaluate(items, brand)
    counts = {s: sum(1 for d in dets if d['severity'] == s) for s in ('high', 'medium', 'low')}
    summary = {'sources': statuses, 'stats': stats, 'counts': counts}
    storage.save_scan_results(dets, summary, started)
    return summary


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def send(self, code, obj, ctype='application/json'):
        body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        self.send_response(code); self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)

    def body(self):
        n = int(self.headers.get('Content-Length') or 0)
        return json.loads(self.rfile.read(n) or b'{}')

    def do_GET(self):
        u = urlparse(self.path); q = {k: v[0] for k, v in parse_qs(u.query).items()}
        try:
            if u.path == '/api/brand': return self.send(200, storage.get_brand() or {})
            if u.path == '/api/detections':
                return self.send(200, {'items': storage.list_detections(q.get('kind'), q.get('severity'), q.get('status')),
                                       'last_scan': storage.last_scan()})
            if u.path in ('/', '/index.html'):
                with open(os.path.join(ROOT, 'static', 'index.html'), 'rb') as f:
                    return self.send(200, f.read(), 'text/html; charset=utf-8')
            self.send(404, {'error': 'not found'})
        except Exception as e: self.send(500, {'error': str(e)})

    def do_PUT(self): self.do_POST()

    def do_POST(self):
        u = urlparse(self.path)
        try:
            data = self.body()
            if u.path == '/api/brand':
                clean, errors, warnings = brand_profile.validate(data)
                if errors: return self.send(422, {'errors': errors, 'warnings': warnings})
                storage.save_brand(clean); return self.send(200, {'brand': clean, 'warnings': warnings})
            if u.path == '/api/demo':
                with open(os.path.join(ROOT, 'data', 'demo_brand.json'), encoding='utf-8') as f:
                    clean, _, warnings = brand_profile.validate(json.load(f))
                storage.save_brand(clean); return self.send(200, {'brand': clean, 'warnings': warnings})
            if u.path == '/api/scan': return self.send(200, run_scan())
            if u.path == '/api/check':   # score a single name/app on the spot
                brand = storage.get_brand()
                if not brand: return self.send(400, {'error': 'Create a brand profile first.'})
                item = {'kind': data.get('kind', 'social'), 'platform': data.get('platform', ''), 'name': data.get('name', ''),
                        'handle': data.get('handle', ''), 'developer': data.get('developer', ''), 'bio': data.get('bio', ''),
                        'description': data.get('description', ''), 'link': data.get('link', ''), 'logo_hash': data.get('logo_hash', ''),
                        'app_id': data.get('app_id', '')}
                if detection.is_official(item, brand): return self.send(200, {'official': True, 'score': 0, 'severity': None, 'reasons': []})
                return self.send(200, {'official': False, **detection.assess(item, brand)})
            if u.path.startswith('/api/detections/') and u.path.endswith('/status'):
                if data.get('status') not in ('new', 'confirmed', 'dismissed'): return self.send(422, {'error': 'bad status'})
                storage.set_status(int(u.path.split('/')[3]), data['status']); return self.send(200, {'ok': True})
            self.send(404, {'error': 'not found'})
        except ValueError as e: self.send(400, {'error': str(e)})
        except Exception as e: self.send(500, {'error': str(e)})


if __name__ == '__main__':
    storage.init()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    print(f'BrandGuard running at http://localhost:{port}')
    ThreadingHTTPServer(('127.0.0.1', port), Handler).serve_forever()
