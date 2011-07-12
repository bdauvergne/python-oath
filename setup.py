#!/usr/bin/python
from distutils.core import setup
import oath

setup(name='oath',
        version=oath.VERSION,
        license='MIT',
        description='Python implementation of the three main OATH specifications: HOTP, TOTP and OCRA',
        url='http://github.con/bdauvergne/python-oath.git',
        author='Benjamin Dauvergne',
        author_email='bdauvergne@entrouvert.com',
        packages=['oath'])
