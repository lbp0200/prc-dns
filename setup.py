# /usr/bin/env python2
# coding=utf-8
from codecs import open
from os import path

from setuptools import setup, find_packages

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='prc-dns',
    version='0.0.1',
    description=u'准确、CDN友好的DNS软件，使用DNS-Over-HTTPS',
    long_description=long_description,
    url='https://github.com/lbp0200/prc-dns',
    author='lbp0200',
    author_email='lbp0408@gmail.com',

    license='unlicense',

    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: Python Software Foundation License',
        'Programming Language :: Python :: 2.7',
    ],

    keywords='DNS',

    packages=find_packages(exclude=['contrib', 'php', 'docs', 'tests']),

    install_requires=['dnslib', 'requests[socks]', 'enum34', 'IPy'],

    extras_require={
        'dev': ['check-manifest'],
        'test': ['coverage'],
    },

    data_files=[],

    entry_points={
        'console_scripts': [
            'prcdns=prcdns.index:main',
        ],
    },
)
