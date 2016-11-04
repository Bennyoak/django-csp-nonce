import base64
import nacl.secret
import nacl.utils


def generate_nonce():
    """ Return a unique base64 encoded nonce hash """
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    return str(base64.b64encode(nonce))


def get_header(response):
    """ Check for CSP header type. Return dict with header and values """
    policies = [
        "Content-Security-Policy",
        "Content-Security-Policy-Report-Only"
    ]

    for p in policies:
        try:
            name = p
            csp = response[p]
            return {'name': name, 'csp': csp}
        except KeyError:
            continue

    return False
