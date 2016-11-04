import unittest
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
