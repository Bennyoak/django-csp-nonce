from django.http import HttpResponse
from django.test import RequestFactory
from django.test.utils import override_settings

from csp_nonce.middleware import CSPNonceMiddleware
from csp_nonce.context_processors import nonce


rf = RequestFactory()


@override_settings(CSP_NONCE_STYLE=True, CSP_NONCE_SCRIPT=True)
def test_context_processor():
    """ Nonce received in template context """
    nmw = CSPNonceMiddleware()
    request = rf.get('/')
    nmw.process_request(request)

    ctx_script = nonce(request)['CSP_NONCE.script']
    ctx_style = nonce(request)['CSP_NONCE.style']
    assert ctx_script == 'nonce="{}"'.format(request.script_nonce)
    assert ctx_style == 'nonce="{}"'.format(request.style_nonce)


@override_settings(CSP_NONCE_SCRIPT=True)
def test_template_header_match():
    """ Basically asserting that the template context and header match """
    nmw = CSPNonceMiddleware()
    header = "Content-Security-Policy"
    csp = "script-src 'self';"
    request = rf.get('/')
    nmw.process_request(request)

    response = HttpResponse()
    response[header] = csp
    rp = nmw.process_response(request, response)

    ctx_script = nonce(request)['CSP_NONCE.script']
    assert ctx_script.replace('"', '').replace('=', '-') in rp[header]
