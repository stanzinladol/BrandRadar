import json, os, unittest
import detection, connectors, brand_profile

D = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
BRAND = brand_profile.validate(json.load(open(os.path.join(D, 'demo_brand.json'), encoding='utf-8')))[0]


class T(unittest.TestCase):
    def setUp(self):
        self.items, self.status = connectors.collect(BRAND)
        self.dets, self.stats = detection.evaluate(self.items, BRAND)
        self.flagged = {(d.get('app_id') or d['handle']) for d in self.dets}

    def test_official_assets_excluded(self):
        self.assertEqual(self.stats['excluded_official'], 6)
        for h in ('acmebank', 'AcmeBank', 'AcmeBankOfficial', 'acme-bank', 'com.acmebank.mobile', '1234567890'):
            self.assertNotIn(h, self.flagged)

    def test_impersonators_flagged(self):
        for h in ('acme_bank_support', 'AcrneBank', 'acme.bank.customer.care', 'acmebnak', 'acme-bank-ltd',
                  'com.quickapps.acmesecure', 'com.freetools.acmebankmobile', '9988776655'):
            self.assertIn(h, self.flagged, h)

    def test_benign_not_overflagged(self):
        for h in ('acmebakery', 'acme.bank.fans', 'com.calclabs.acmecalc', '5544332211'):
            self.assertNotIn(h, self.flagged, h)

    def test_lookalike_variants(self):
        n = lambda s: detection.name_signal(s, ['Acme Bank'], set())[0]
        self.assertGreaterEqual(n('Acme  Bank'), 45)    # spacing
        self.assertGreaterEqual(n('Acm3 B@nk'), 45)     # character swap
        self.assertGreaterEqual(n('Acme Bnak'), 40)     # transposition
        self.assertGreaterEqual(n('Acme Bank Support'), 35)  # added word
        self.assertLess(n('Acme Bakery'), 25)
        self.assertLess(n('Blue Ocean Travel'), 1)

    def test_unavailable_source_is_graceful(self):
        bad = [s for s in self.status if not s['ok']]
        self.assertEqual([s['name'] for s in bad], ['TikTok'])

    def test_profile_validation(self):
        _, errors, _ = brand_profile.validate({'name': '', 'domains': ['not a domain'], 'logo_hash': 'zz'})
        self.assertEqual(len(errors), 3)


if __name__ == '__main__':
    unittest.main()
