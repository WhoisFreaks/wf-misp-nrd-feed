from setuptools import setup, find_packages

setup(
    name="wf-misp-nrd-feed",
    version="1.0.0",
    description="Publish the WhoisFreaks Newly Registered Domains feed as a MISP feed",
    url="https://github.com/WhoisFreaks/wf-misp-nrd-feed",
    license="MIT",
    packages=find_packages(include=["src", "src.*"]),
    python_requires=">=3.9",
    install_requires=["requests>=2.28.0"],
    extras_require={"test": ["pytest>=7.0", "pymisp>=2.4.150", "ruff"]},
    entry_points={"console_scripts": ["misp-nrd-feed=src.main:main"]},
    classifiers=[
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
)