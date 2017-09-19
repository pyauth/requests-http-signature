#!/usr/bin/env python

import os, glob
from setuptools import setup, find_packages

setup(
    name='requests-http-signature',
    version='0.0.3',
    url='https://github.com/kislyuk/requests-http-signature',
    license='Apache Software License',
    author='Andrey Kislyuk',
    author_email='kislyuk@gmail.com',
    description="A Requests auth module for HTTP Signature",
    long_description=open('README.rst').read(),
    packages=find_packages(exclude=['test']),
    include_package_data=True,
    platforms=['MacOS X', 'Posix'],
    test_suite='test',
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Development Status :: 5 - Production/Stable',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    install_requires=[
        "requests"
    ],
    extras_require={
        "rsa": ["cryptography >= 1.8.2"],
        "ecdsa": ["cryptography >= 1.8.2"]
    }
)
