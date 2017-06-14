Django-CSP-Nonce (beta)
=======================

|Build Status|

DCN is a Content-Security-Policy nonce injection support system for
Django and CSP.

| It provides for on-the-fly nonce creation and deployment. Once
  installed, DCN will generate a unique nonce
| for each request (one for ``script-src`` and a separate one for
  ``style-src`` directives) append the nonce to the
| CSP header, then make the nonce(s) accessible to the templates via the
  Django Context Processors.

| DCN stays out of the way of `Django-CSP`_ and can operate
| independently with any method of CSP insertion that passes through
  Django Middleware.

Disclosure
----------

-  This code has not been through a third party security audit.
-  I’ve successfully tested this locally with ``pypy-5.4.1``. TravisCI
   has confirmed this doesn’t work with their version.

Installation
------------

``pip install django-csp-nonce``

Add DCN to ``MIDDLEWARE_CLASSES``:

.. code:: python

    MIDDLEWARE_CLASSES = (
        [ ... ]
        'csp_nonce.middleware.CSPNonceMiddleware',
        # Make sure you put it *above* django-csp if you're using it
        [ ... ]
    )

Add DCN to ``context_processors``:

.. code:: python

    TEMPLATES = [
        {
            'BACKEND': 'django.template.backends.django.DjangoTemplates',
            'DIRS': [...],
            'APP_DIRS': True,
            'OPTIONS': {
                'context_processors': [
                    'csp_nonce.context_processors.nonce',
                    [ ... ]
                ],
            },
        },
    ]

Finally, add DCN directives to settings:

.. code:: python

    CSP_NONCE_SCRIPT = False  # True if you want to use it
    CSP_NONCE_STYLE = False  # True if you want to use it
    CSP_FLAG_STRICT = False  # True to include strict-dynamic in CSP

Usage
-----

DCN takes care of nonce generation for you. As you work
on your templates, pull in your specific nonce from the context:

.. code:: django

    <script type="text/javascript" {{ script_nonce }}>
    ...
    </script>

    <style {{ style_nonce }}>
    ...
    </style>

Dependencies
------------

-  Django

Known issues
------------

-  Nonce sync breaks on ``settings.DEBUG=True``

.. _Django-CSP: http://django-csp.readthedocs.io/en/latest/

.. |Build Status| image:: https://travis-ci.org/Bennyoak/django-csp-nonce.svg?branch=master
   :target: https://travis-ci.org/Bennyoak/django-csp-nonce
