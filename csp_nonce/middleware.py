import re
from .utils import generate_nonce, get_header
from django.conf import settings


class CSPNonceMiddleware(object):
    """ Nonce Injection middleware for CSP. """

    def __init__(self, *args, **kwargs):
        self.csp_nonce_script = getattr(settings, 'CSP_NONCE_SCRIPT', None)
        self.csp_nonce_style = getattr(settings, 'CSP_NONCE_STYLE', None)

    def process_request(self, request):
        """ Pack nonce hash for activated directive(s) into request """
        if self.csp_nonce_script:
            request.script_nonce = generate_nonce()

        if self.csp_nonce_style:
            request.style_nonce = generate_nonce()

    def process_response(self, request, response):
            """ Append availabe nonce hashes to their respective directives """
            header = get_header(response)

            if not header:
                return response

            nonce_request = {
                'script':  getattr(request, 'script_nonce', None),
                'style':  getattr(request, 'style_nonce', None)
            }

            patt = re.compile(r"\b(script|style)-src\s(.*?)(?=;)")

            search = re.findall(patt, header['csp'])

            if search:
                for (a, b) in search:
                    if a in ('style', 'script'):
                        header['csp'] = header['csp'].replace(
                            b, b + " 'nonce-{}'".format(nonce_request[a])
                        )

                if header:
                    response[header['name']] = header['csp']

            return response
