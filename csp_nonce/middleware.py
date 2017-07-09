import logging
from .utils import generate_nonce, get_header, nonce_exists
from django.conf import settings


LOG = logging.getLogger(__name__)

try:
    from django.utils.deprecation import MiddlewareMixin
except ImportError:
    class MiddlewareMixin(object):
        """ Django 1.10+ """
        pass


class CSPNonceMiddleware(MiddlewareMixin):
    """ Nonce Injection middleware for CSP. """

    def process_request(self, request):
        """Django Middleware request processor.

        Pack nonce hash for activated directive(s) into request.

        Returns:
            None
        """
        csp_nonce_script = getattr(settings, 'CSP_NONCE_SCRIPT', False)
        csp_nonce_style = getattr(settings, 'CSP_NONCE_STYLE', False)

        if csp_nonce_script:
            request.script_nonce = generate_nonce()

        if csp_nonce_style:
            request.style_nonce = generate_nonce()

    def process_response(self, request, response):
            """Django Middleware response processor.

            Append available nonce hashes to their respective directives

            Returns:
                None
            """
            header = get_header(response)

            if not header:
                return response

            nonce_found, has_nonce = nonce_exists(response)
            if has_nonce:
                LOG.error("Nonce already exists: {}".format(nonce_found))
                return response

            nonce_request = {
                'script':  getattr(request, 'script_nonce', None),
                'style':  getattr(request, 'style_nonce', None)
            }

            csp_flag_strict = getattr(settings, 'CSP_FLAG_STRICT', False)

            csp_split = header['csp'].split(';')
            new_csp = []

            for p in csp_split:
                for x in ('script', 'style'):
                    if p.lstrip().startswith(x) and nonce_request[x]:
                        p += " 'nonce-{}'".format(nonce_request[x])
                        if x == 'script' and csp_flag_strict:
                            p += " 'strict-dynamic'"
                new_csp.append(p)

            response[header['name']] = ";".join(new_csp)

            return response
