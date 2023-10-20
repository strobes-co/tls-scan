from setuptools import setup, find_packages

setup(
    name='tls_scan',
    version='1.0',
    packages=find_packages(),
    install_requires=[
        'ipaddress'
    ],
    entry_points={
        'console_scripts': [
            'tls_scan=tls_scan.main:main',
        ],
    },
)
