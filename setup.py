import sys
import os
import codecs
from setuptools import setup, find_packages


version = '1.0b20'


if sys.argv[-1] == 'publish':
    register = "twine register dist/django-csp-nonce-{}-py2.py3-none-any.whl" \
        .format(version)
    os.system(register)
    os.system('twine upload dist/*')
    print('You probably want to also tag the version now:')
    print('  git tag -a %s -m "version %s"' % (version, version))
    print('  git push --tags')
    sys.exit()


def read(*parts):
    filename = os.path.join(os.path.dirname(__file__), *parts)
    with codecs.open(filename, encoding='utf-8') as fp:
        return fp.read()


install_requires = [
    'Django>=1.6,<1.11',
]


test_requires = [
    'pytest==2.9.1',
    'pytest-django==2.9.1',
    'pytest-flakes==1.0.1',
    'pytest-pep8==1.0.6',
    'pep8==1.4.6',
    'mock==1.0.1',
    'django-csp',  # always install the latest
]


setup(
    name='django_csp_nonce',
    version=version,
    description='Nonce support for Content Security Policy in Django.',
    long_description=read('README.rst'),
    keywords="CSP Content Security Policy Nonce Django",
    author='Bennyoak',
    author_email='benny@spideroak.com',
    maintainer='Bennyoak',
    maintainer_email='benny@spideroak.com',
    url='http://github.com/SpiderOak/django-csp-nonce',
    license='MPL 2.0',
    packages=find_packages(),
    install_requires=install_requires,
    extras_require={
        'tests': test_requires,
    },
    include_package_data=True,
    zip_safe=False,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Programming Language :: Python',
        'License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)',
        'Operating System :: OS Independent',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        # 'Programming Language :: Python :: Implementation :: pypy',
        'Programming Language :: Python :: Implementation :: CPython',
        'Framework :: Django',
    ]
)
