""" These tests are just to make sure I say out of the way
    of django-csp processing.
    My assertion is that if I'm out of the way of the
    standard build process and I respect _csp_exempt,
    all is good """

from django.http import HttpResponse
from django.test import RequestFactory
from django.test.utils import override_settings


from csp_nonce.middleware import CSPNonceMiddleware
from csp.middleware import CSPMiddleware

HEADER = "Content-Security-Policy"

mw = CSPMiddleware()
rf = RequestFactory()


@override_settings(CSP_NONCE_SCRIPT=True)
def test_csp_compatible():
    nmw = CSPNonceMiddleware()
    request = rf.get('/')
    nmw.process_request(request)
    assert getattr(request, 'script_nonce', None)

    response = HttpResponse()
    mw.process_response(request, response)
    nmw.process_response(request, response)

    assert request.script_nonce in response[HEADER]


@override_settings(CSP_NONCE_SCRIPT=True)
def test_csp_exempt_compatible():
    nmw = CSPNonceMiddleware()
    request = rf.get('/')
    nmw.process_request(request)
    assert getattr(request, 'script_nonce', None)

    response = HttpResponse()
    response._csp_exempt = True
    mw.process_response(request, response)
    nmw.process_response(request, response)

    assert HEADER not in response

# TODO: Rearrange tests to make sure it stays
# out of the way of django-csp latest 
