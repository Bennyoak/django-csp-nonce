from __future__ import unicode_literals
import base64
import nacl.secret
import nacl.utils


def generate_nonce():
    """ Return a unique base64 encoded nonce hash """
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    return "{}".format(base64.b64encode(nonce))


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
            if all(map(lambda p: p in directive, ['script-src', 'nonce-'])):
                nonce_found['script'] = directive
            if all(map(lambda p: p in directive, ['style-src', 'nonce-'])):
                nonce_found['style'] = directive

    return nonce_found


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
