CSP_REPORT_ONLY = False
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'", "https://scripts.trustedurl.com")
CSP_IMG_SRC = ("'self'", "*.trusted-example.com", "data")
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'", "*.styles.trustedurl.com")

CSP_NONCE_SCRIPT = False
CSP_NONCE_STYLE = False
CSP_FLAG_STRICT = False


INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'csp_nonce',
    'csp',
)

SECRET_KEY = 'csp-nonce-test-key'
