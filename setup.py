#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
        name="spurge-rgtpd",
        version="0.5.1",
        packages=find_packages(),

        # I'd like to allow both xinetd and standalone daemon.
        # How?
        entry_points={
            'console_scripts': [
                'spurge_rgtpd = spurge_rgtp.cli:serve',
                ],
            },

        install_requires=['docutils>=0.3'],

        author="Marnanel Thurman",
        author_email="marnanel@thurman.org.uk",
        description="file:README.rst",
        license="GPL 2.0",
        keywords="spurge rgtpd rgtp daemon",
        url="https://github.com/marnanel/spurge",

        )
