import base64
import nacl.secret
import nacl.utils
import re

from django.conf import settings


class CSPNonceMiddleware(object):
    """ Nonce Injection middleware for CSP. """

    def __init__(self, *args, **kwargs):
        self.csp_nonce_script = getattr(settings, 'CSP_NONCE_SCRIPT', None)
        self.csp_nonce_style = getattr(settings, 'CSP_NONCE_STYLE', None)

    def _generate_nonce(self):
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        return base64.b64encode(nonce)

    def process_request(self, request):
        if self.csp_nonce_script:
            request.script_nonce = self._generate_nonce()

        if self.csp_nonce_style:
            request.style_nonce = self._generate_nonce()

    def process_response(self, request, response):

            def _get_header():
                policies = [
                    "Content-Security-Policy",
                    "Content-Security-Policy-Report-Only"
                ]

                for p in policies:
                    try:
                        name = p
                        csp = response[p]
                        return {'name': name, 'csp': csp}
                    except:
                        continue

                return False

            header = _get_header()

            if not header:
                return response

            script = getattr(request, 'script_nonce', None)
            style = getattr(request, 'style_nonce', None)

            patt = re.compile(r"\b(script|style)-src\s(.*?)(?=;)")

            search = re.findall(patt, header['csp'])

            if search:
                nc = " 'nonce-{}'"
                for (a, b) in search:
                    if a == 'script':
                        header['csp'] = header['csp'].replace(
                            b, b + nc.format(script)
                        )
                    if a == 'style':
                        header['csp'] = header['csp'].replace(
                            b, b + nc.format(style)
                        )

                if header:
                    response[header['name']] = header['csp']

            return response
