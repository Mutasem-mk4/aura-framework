import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="aura-cli",
    version="19.5.0",
    author="Aura Security",
    author_email="security@aura.local",
    description="The Apex Predator. Next-generation, autonomous, AI-driven Bug Bounty and Penetration Testing framework.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Mutasem-mk4/Aura-Predator",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Private :: Do Not Upload",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.10",
    install_requires=[
        "rich>=13.0.0",
        "aiohttp>=3.8.0",
        "httpx>=0.24.0",
        "curl_cffi>=0.5.9",
        "playwright>=1.38.0",
        "google-generativeai>=0.3.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=4.9.0",
        "PyYAML>=6.0",
        "jinja2>=3.1.2",
    ],
    entry_points={
        "console_scripts": [
            "aura=aura.cli:main",
        ],
    },
)
