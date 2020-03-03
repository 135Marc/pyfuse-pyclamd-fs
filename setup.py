from setuptools import setup

setup(name='ssitp3',
    version='1.0',
    description='Authenticated secure fuse file system',
    packages=['pyfuse3'],
    install_requires=[
        'pyfuse3',
        'cryptography',
        'python-pam',
        'pyclamd'
    ],
    zip_safe=False)