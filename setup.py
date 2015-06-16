#!/usr/bin/python
from setuptools import setup

setup(name='oath',
        version='1.4.1',
        license='BSD 3-clause',
        description='Python implementation of the three main OATH specifications: HOTP, TOTP and OCRA',
        url='https://github.com/bdauvergne/python-oath',
        author='Benjamin Dauvergne',
        author_email='bdauvergne@entrouvert.com',
        packages=['oath'],
        test_suite='tests',
        classifiers=[
            "Development Status :: 5 - Production/Stable",
            'Intended Audience :: Developers',
            "License :: OSI Approved :: MIT License",
            "Operating System :: OS Independent",
            "Programming Language :: Python",
            "Programming Language :: Python :: 2",
            "Programming Language :: Python :: 3",
            "Topic :: Security",
            "Topic :: Security :: Cryptography",
        ])
