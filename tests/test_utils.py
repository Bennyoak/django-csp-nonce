from csp_nonce import utils


def test_nonce_generated():
    nonce = utils.generate_nonce()
    assert nonce is not None


def test_get_header():
    response = {'Content-Security-Policy': 'Hola, Mundo!'}
    gh = utils.get_header(response)
    assert gh is not None


def test_get_header_false():
    response = {'ImALittleTeaPot': 'Short and stout'}
    gh = utils.get_header(response)
    assert gh is False
