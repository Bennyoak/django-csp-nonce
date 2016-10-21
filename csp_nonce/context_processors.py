"""
Context processor for CSP nonce template injection.

Usage:
    Add the CSP_NONCE context to any inline script or style tag.
    <script type="text/javascript" {{ CSP_NONCE.script|safe }}>

    The result from the compile template will look like:
    <script type="text/javascript" nonce="EDNnf03nceIOfn39fn3e9h3sdfa">
"""


def nonce(request):
    script = getattr(request, 'script_nonce', None)
    style = getattr(request, 'style_nonce', None)

    return {
        'CSP_NONCE.script': 'nonce="{}"'.format(script),
        'CSP_NONCE.style': 'nonce="{}"'.format(style),
    }
