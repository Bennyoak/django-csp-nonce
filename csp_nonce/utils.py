from __future__ import unicode_literals
import base64
import os

# Number of random bytes in the nonce:
NONCE_BYTES = 24

def generate_nonce():
    """ Return a unique base64 encoded nonce hash."""
    nonce = os.urandom(NONCE_BYTES)
    return base64.b64encode(nonce).decode()


def nonce_exists(response):
    """ Check for preexisting nonce in style and script """
    try:
        csp = response['Content-Security-Policy']
    except KeyError:
        csp = response['Content-Security-Policy-Report-Only']

    nonce_found = {}

    if csp:
        csp_split = csp.split(';')
        for directive in csp_split:
            if 'nonce-' not in directive:
                continue
            if 'script-src' in directive:
                nonce_found['script'] = directive
            if 'style-src' in directive:
                nonce_found['style'] = directive

    has_nonce = any(nonce_found)

    return nonce_found, has_nonce


def get_header(response):
    """ Check for CSP header type. Return dict with header and values """
    policies = [
        "Content-Security-Policy",
        "Content-Security-Policy-Report-Only"
    ]

    try:
        name = policies[0]
        csp = response[policies[0]]
    except KeyError:
        try:
            name = policies[1]
            csp = response[policies[1]]
        except KeyError:
            return False

    return {'name': name, 'csp': csp}
