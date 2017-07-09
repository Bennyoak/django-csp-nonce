"""Context processor for CSP nonce template injection.

Usage:
    Add the nonce context to any inline script or style tag.
    <script type="text/javascript" {{ script_nonce }}>

    The result from the compile template will look like:
    <script type="text/javascript" nonce="EDNnf03nceIOfn39fn3e9h3sdfa">
"""


def nonce(request):
    """ Pass the nonce cases to their respective template calls.

    Args:
        request (:obj:) Django request object

    Returns:
        bool: False in template if settings are not activated
        dict:
            script_nonce (str): Cryptographic nonce for use in <script> tags.
            style_nonce (str): Cryptographic nonce for use in <style> tags.

    """
    script = getattr(request, 'script_nonce', False)
    style = getattr(request, 'style_nonce', False)

    # Will show False in template if settings not activated
    return {
        'script_nonce': 'nonce={}'.format(script),
        'style_nonce': 'nonce={}'.format(style)
    }
