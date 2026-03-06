from setuptools import setup, find_packages

setup(
    name="aura",
    version="14.0.0",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "aura=aura.cli:cli",
        ],
    },
    install_requires=[],
)
