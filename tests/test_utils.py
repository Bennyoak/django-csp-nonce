import unittest
from django.http import HttpResponse
from csp_nonce import utils


class TestUtils(unittest.TestCase):
    def test_nonce_generated(self):
        nonce = utils.generate_nonce()
        self.assertTrue(nonce is not None)

    def test_get_header(self):
        response = {'Content-Security-Policy': 'Hola, Mundo!'}
        gh = utils.get_header(response)
        self.assertTrue(gh is not None)

    def test_get_header_false(self):
        response = {'ImALittleTeaPot': 'Short and stout'}
        gh = utils.get_header(response)
        self.assertFalse(gh)

    def test_get_header_raises_key_error(self):
        response = {'ThisLittlePiggy': 'Had no CSP Header'}
        with self.assertRaises(KeyError):
            response['Content-Security-Policy']
            response['Content-Security-Policy-Report-Only']

    def test_nonce_exists_script(self):
        csp = "script-src *.goof.com 'nonce-123/AB+C';" + \
            " style-src 'self' 'unsafe-inline';"
        response = HttpResponse()
        response['Content-Security-Policy'] = csp
        nonce_found, has_nonce = utils.nonce_exists(response)
        self.assertTrue(has_nonce)
        self.assertEqual(
            "script-src *.goof.com 'nonce-123/AB+C'",
            nonce_found['script']
        )
        self.assertIsNone(nonce_found.get('style', None))

    def test_nonce_exists_style(self):
        csp = "sctipt-src *.goof.com;" + \
            " style-src 'self' https://stuff.things.com 'nonce-123/AB+C';"
        response = HttpResponse()
        response['Content-Security-Policy'] = csp
        nonce_found, has_nonce = utils.nonce_exists(response)
        self.assertTrue(has_nonce)
        self.assertEqual(
            " style-src 'self' https://stuff.things.com 'nonce-123/AB+C'",
            nonce_found['style']
        )
        self.assertIsNone(nonce_found.get('script', None))

    def test_nonce_exists_empty(self):
        csp = "default-src *.goof.com;" + \
            " font-src 'self' https://stuff.things.com;"
        response = HttpResponse()
        response['Content-Security-Policy'] = csp
        nonce_found, has_nonce = utils.nonce_exists(response)
        self.assertFalse(has_nonce)
        self.assertIsNone(nonce_found.get('script', None))
        self.assertIsNone(nonce_found.get('style', None))
