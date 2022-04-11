#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='requests-http-signature',
    version='0.2.0',
    url='https://github.com/pyauth/requests-http-signature',
    license='Apache Software License',
    author='Andrey Kislyuk',
    author_email='kislyuk@gmail.com',
    description="A Requests auth module for HTTP Message Signatures",
    long_description=open('README.rst').read(),
    use_scm_version={
        "write_to": "requests_http_signature/version.py",
    },
    setup_requires=['setuptools_scm >= 3.4.3'],
    install_requires=[
        "http-message-signatures >= 0.2.2",
        "http-sfv >= 0.9.3",
        "requests >= 2.27.1"
    ],
    extras_require={
        "tests": [
            "flake8",
            "coverage",
            "build",
            "wheel",
            "mypy",
        ]
    },
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
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
)
