# setup.py
from setuptools import setup, find_packages

setup(
    name="sentra",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "cryptography==42.0.5",
        "argon2-cffi==23.1.0",
        "pyotp==2.9.0",
        "rich==13.7.0",
    ],
    python_requires=">=3.8",
)
