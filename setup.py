# -*- coding: utf-8 -*-
from setuptools import find_packages, setup  # type: ignore

with open('README.rst', 'r') as fh:
    long_description = fh.read()

setup(
    name='burp_exporter',
    version='0.1.0',
    author='Stefan Valouch',
    author_email='svalouch@valouch.com',
    description='Prometheus exporter for burp server',
    long_description=long_description,
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    include_package_data=True,
    zip_safe=False,
    license='BSD-3-Clause',
    url='https://github.com/svalouch/burp_exporter',
    platforms='any',
    python_requires='>=3.6',

    install_requires=[
        'prometheus_client>=0.6.0',
        'pydantic>=0.30.0',
        'pyyaml>=3.12',
    ],
    extras_require={
        'dev': [
            'tox',
            'pytest',
        ],
        'docs': [
            'Sphinx>=2.0',
        ]
    },
    entry_points={
        'console_scripts': [
            'burp_exporter=burp_exporter.cli:cli',
        ],
    },

    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: System :: Monitoring',
    ]
)
