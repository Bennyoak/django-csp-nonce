# Django-CSP-Nonce

DCN is a Content-Security-Policy nonce injection support system for Django and CSP.

It provides for on-the-fly nonce creation and deployment. Once installed, DCN will generate a unique nonce  
for each request (one for `scritp-src` and a seperate one for `style-src` directives) append the nonce to the  
CSP header, then make the nonce(s) accessible to the templates via the Django Context Processors.

DCN stays out of the way of [Django-CSP](http://django-csp.readthedocs.io/en/latest/) and can operate  
independently with any method of CSP insertion that passes through Django Middleware.
