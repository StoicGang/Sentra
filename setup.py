from setuptools import setup, find_packages

setup(
    name="sentra",
    version="0.1.0",
    author="StoicGang",
    author_email="contact@stoicgang.local",
    description="Sentra — A secure CLI & Web Password Manager",
    url="https://github.com/StoicGang/Sentra",
    license="MIT",
    packages=find_packages(),
    include_package_data=True, 
    install_requires=[
        "cryptography>=42.0.5",
        "argon2-cffi>=23.1.0",
        "pyotp>=2.9.0",
        "python-dotenv>=1.0.0",
        "pyperclip>=1.11.0",
        "fastapi>=0.109.0",
        "uvicorn[standard]>=0.27.0",
        "pydantic>=2.6.0",
        "click>=8.0.0",
        "rich>=13.0.0",
        "tabulate>=0.9.0",
        "colorama>=0.4.0",
        "sqlite-utils>=3.30"
    ],
    python_requires=">=3.8",
)
