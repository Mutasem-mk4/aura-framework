from setuptools import setup, find_packages

setup(
    name="aura-offensive",
    version="25.0",
    packages=find_packages(),
    install_requires=[
        "rich",
        "httpx",
        "aiohttp",
        "beautifulsoup4",
        "python-dotenv",
        "jsbeautifier",
    ],
    entry_points={
        "console_scripts": [
            "aura=aura.cli_v2:main",
        ],
    },
)
