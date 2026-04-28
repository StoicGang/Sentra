from setuptools import setup, find_packages

setup(
    name="sentra",
    version="0.1.0",
    packages=find_packages(),
    include_package_data=True, 
    install_requires=[
        "cryptography==42.0.5",
        "argon2-cffi==23.1.0",
        "pyotp==2.9.0",
        "python-dotenv==1.0.1",
        "pyperclip==1.11.0",
        "fastapi==0.109.2",
        "uvicorn[standard]==0.27.1",
        "pydantic==2.6.1",
    ],
    python_requires=">=3.8",
)
