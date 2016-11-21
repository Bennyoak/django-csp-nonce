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
nmw = CSPNonceMiddleware()


@override_settings(CSP_NONCE_SCRIPT=True)
def test_nonce_request():
    """ Assert nonce sent to request """
    request = rf.get('/')
    nmw.process_request(request)
    assert getattr(request, 'script_nonce', None)


@override_settings(CSP_NONCE_SCRIPT=True)
def test_script_nonce_response():
    """ Script nonce gets pushed to response header """
    request = rf.get('/')
    nmw.process_request(request)

    response = HttpResponse()
    response[HEADER] = CSP
    nmw.process_response(request, response)
    assert request.script_nonce in response[HEADER]


@override_settings(CSP_NONCE_STYLE=True)
def test_style_nonce_response():
    """ Style nonce gets pushed to response header """
    request = rf.get('/')
    nmw.process_request(request)

    response = HttpResponse()
    response[HEADER] = CSP
    nmw.process_response(request, response)
    assert request.style_nonce in response[HEADER]


@override_settings(CSP_NONCE_STYLE=True, CSP_NONCE_SCRIPT=True)
def test_all_nonce_response():
    """ Assert both nonce cases are passed """
    request = rf.get('/')
    nmw.process_request(request)

    response = HttpResponse()
    response[HEADER] = CSP
    nmw.process_response(request, response)
    assert response[HEADER].count('nonce') == 2
    assert request.style_nonce in response[HEADER]
    assert request.script_nonce in response[HEADER]


def test_empty_nonce_response():
    """ Nonce middleware stays out of
        the way if not called """
    request = rf.get('/')
    nmw.process_request(request)

    response = HttpResponse()
    nmw.process_response(request, response)
    assert HEADER not in response


@override_settings(CSP_NONCE_SCRIPT=True)
def test_unique_nonce_per_request():
    """ Make sure request gets a new nonce """
    request1 = rf.get('/')
    nmw.process_request(request1)

    request2 = rf.get('/')
    nmw.process_request(request2)

    assert request1.script_nonce != request2.script_nonce


@override_settings(CSP_NONCE_SCRIPT=True)
def test_existing_nonce():
    request = rf.get('/')
    nmw.process_request(request)

    response = HttpResponse()
    response[HEADER] = "script-src 'self' 'nonce-123A/B+c'"
    nmw.process_response(request, response)

    assert request.script_nonce not in response[HEADER]


@override_settings(CSP_NONCE_SCRIPT=True, CSP_FLAG_STRICT=True)
def test_strict_dynamic_addition():
    request = rf.get('/')
    nmw.process_request(request)

    response = HttpResponse()
    response[HEADER] = CSP
    nmw.process_response(request, response)
    assert 'strict-dynamic' in response[HEADER]
