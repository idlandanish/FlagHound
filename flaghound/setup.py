#!/usr/bin/env python3
"""
Setup script for FlagHound v2.0
"""
from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read() if fh else ""

setup(
    name="flaghound",
    version="2.0.0",
    author="CTF Team",
    description="Fast CTF triage tool for automating file analysis and flag extraction",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Environment :: Console",
    ],
    python_requires=">=3.6",
    install_requires=[
        "chardet>=4.0.0",
    ],
    entry_points={
        "console_scripts": [
            "flaghound=flaghound.cli:main",
        ],
    },
)
