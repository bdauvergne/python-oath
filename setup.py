#!/usr/bin/python
from distutils.core import setup, Command
from unittest import TextTestRunner, TestLoader
from glob import glob
from os.path import splitext, basename, join as pjoin
import os
import sys

class TestCommand(Command):
    user_options = [ ]

    def initialize_options(self):
        self._dir = os.getcwd()

    def finalize_options(self):
        pass

    def run(self):
        '''
        Finds all the tests modules in tests/, and runs them.
        '''
        testfiles = [ ]
        for t in glob(pjoin(self._dir, 'tests', '*.py')):
            if not t.endswith('__init__.py'):
                testfiles.append('.'.join(
                    ['tests', splitext(basename(t))[0]])
                )

        tests = TestLoader().loadTestsFromNames(testfiles)
        t = TextTestRunner(verbosity = 4)
        res = t.run(tests)
        if res.errors:
            sys.exit(1)

setup(name='oath',
        version='1.2',
        license='MIT',
        description='Python implementation of the three main OATH specifications: HOTP, TOTP and OCRA',
        url='https://github.com/bdauvergne/python-oath',
        author='Benjamin Dauvergne',
        author_email='bdauvergne@entrouvert.com',
        packages=['oath'],
        cmdclass={'test': TestCommand},
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
