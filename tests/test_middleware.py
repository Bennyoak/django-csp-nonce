from django.http import HttpResponse
from django.test import RequestFactory
from django.test.utils import override_settings

from csp_nonce.middleware import CSPNonceMiddleware


HEADER = 'Content-Security-Policy'
CSP = "default-src 'self'; " \
    + "script-src 'self' https://cdn.trusted-example.com 'unsafe-eval'; " \
    + "img-src 'self' *.trusted-example.com data:; " \
    + "style-src 'self', 'unsafe-inline'; "

rf = RequestFactory()


@override_settings(CSP_NONCE_SCRIPT=True)
def test_nonce_request():
    """ Assert nonce sent to request """
    nmw = CSPNonceMiddleware()
    request = rf.get('/')
    nmw.process_request(request)
    assert getattr(request, 'script_nonce', None)


@override_settings(CSP_NONCE_SCRIPT=True)
def test_script_nonce_response():
    """ Script nonce gets pushed to response header """
    nmw = CSPNonceMiddleware()
    request = rf.get('/')
    nmw.process_request(request)

    response = HttpResponse()
    response[HEADER] = CSP
    nmw.process_response(request, response)
    assert request.script_nonce in response[HEADER]


@override_settings(CSP_NONCE_STYLE=True)
def test_style_nonce_response():
    """ Style nonce gets pushed to response header """
    nmw = CSPNonceMiddleware()
    request = rf.get('/')
    nmw.process_request(request)

    response = HttpResponse()
    response[HEADER] = CSP
    nmw.process_response(request, response)
    assert request.style_nonce in response[HEADER]


@override_settings(CSP_NONCE_STYLE=True, CSP_NONCE_SCRIPT=True)
def test_all_nonce_response():
    """ Assert both nonce cases are passed """
    nmw = CSPNonceMiddleware()
    request = rf.get('/')
    nmw.process_request(request)

    response = HttpResponse()
    response[HEADER] = CSP
    nmw.process_response(request, response)
    assert request.style_nonce in response[HEADER]
    assert request.script_nonce in response[HEADER]


def test_empty_nonce_response():
    """ Nonce middleware stays out of
        the way if not called """
    nmw = CSPNonceMiddleware()
    request = rf.get('/')
    nmw.process_request(request)

    response = HttpResponse()
    nmw.process_response(request, response)
    assert HEADER not in response
