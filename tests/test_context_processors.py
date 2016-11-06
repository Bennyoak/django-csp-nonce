from django.http import HttpResponse
from django.test import RequestFactory
from django.test.utils import override_settings

from csp_nonce.middleware import CSPNonceMiddleware
from csp_nonce.context_processors import nonce


rf = RequestFactory()
nmw = CSPNonceMiddleware()


@override_settings(CSP_NONCE_STYLE=True, CSP_NONCE_SCRIPT=True)
def test_context_processor():
    """ Nonce received in template context """
    request = rf.get('/')
    nmw.process_request(request)

    ctx_script = nonce(request)['script_nonce']
    ctx_style = nonce(request)['style_nonce']
    assert ctx_script == 'nonce={}'.format(request.script_nonce)
    assert ctx_style == 'nonce={}'.format(request.style_nonce)


@override_settings(CSP_NONCE_SCRIPT=True)
def test_template_header_match():
    """ Basically asserting that the template context and header match """
    header = "Content-Security-Policy"
    csp = "script-src 'self';"
    request = rf.get('/')
    nmw.process_request(request)

    response = HttpResponse()
    response[header] = csp
    rp = nmw.process_response(request, response)

    ctx_script = nonce(request)['script_nonce']
    assert ctx_script.replace('"', '').replace('=', '-') in rp[header]
