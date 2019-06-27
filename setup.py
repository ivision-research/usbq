#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""The setup script."""
from setuptools import find_packages
from setuptools import setup

requirements = [
    'Click>=6.0',
    'scapy',
    'pluggy',
    'attrs',
    'frozendict',
    'coloredlogs',
    'python-statemachine',
]

setup_requirements = ['pytest-runner']

test_requirements = ['pytest']

setup(
    author="Brad Dixon",
    author_email='brad.dixon@carvesystems.com',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.7',
    ],
    description="New Python programming framework extending Benoît Camredon's USBiquitous USB intrusion toolkit.",
    entry_points={
        'console_scripts': ['usbq=usbq.cli:main'],
        # Pluggy plugin
        'usbq': ['usbq_base = usbq.plugin'],
    },
    install_requires=requirements,
    license="MIT license",
    long_description='USBQ -- Python programming framework for monitoring and modifying USB communications.',
    include_package_data=True,
    keywords='usbq',
    name='usbq',
    packages=find_packages(),
    setup_requires=setup_requirements,
    test_suite='tests',
    tests_require=test_requirements,
    url='https://github.com/rbdixon/usbq',
    version='0.1.0',
    zip_safe=False,
)
