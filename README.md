# Django-CSP-Nonce

DCN is a Content-Security-Policy nonce injection support system for Django and CSP.

It provides for on-the-fly nonce creation and deployment. Once installed, DCN will generate a unique nonce  
for each request (one for `script-src` and a separate one for `style-src` directives) append the nonce to the  
CSP header, then make the nonce(s) accessible to the templates via the Django Context Processors.

DCN stays out of the way of [Django-CSP](http://django-csp.readthedocs.io/en/latest/) and can operate  
independently with any method of CSP insertion that passes through Django Middleware.

## Disclosure
This code has not been through a third party security audit.

## Installation

WIP - Ultimately, this will be available through pip

Add DCN to `MIDDLEWARE_CLASSES`:
```python
MIDDLEWARE_CLASSES = (
    [ ... ]
    'csp_nonce.middleware.CSPNonceMiddleware',
    # Make sure you put it *above* django-csp if you're using it
    [ ...]
)
```

Add DCN to `context_processors`:
```python
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [...],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'csp_nonce.context_processors.nonce',
                'django.contrib.auth.context_processors.auth',
                'django.template.context_processors.debug',
                'django.template.context_processors.i18n',
                'django.template.context_processors.media',
                'django.template.context_processors.static',
                'django.template.context_processors.tz',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]
```

Finally, add DCN directives to settings:
```python
CSP_NONCE_SCRIPT = False  # True if you want to use it
CSP_NONCE_STYLE = False  # True if you want to use it
```


## Usage
DCN takes care of nonce generation for you using [pynacl](https://github.com/pyca/pynacl).
As you work on your templates, pull in your specific nonce from the context:
```django
<script type="text/javascript" {{ CSP_NONCE.script|safe }}>
...
</script>

<style {{ CSP_NONCE.style|safe }}>
...
</style>
```
*NOTE:* Make sure you use the `safe` templatetag!


## Dependencies

- PyNacl
- Django
