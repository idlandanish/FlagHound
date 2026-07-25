from setuptools import setup, find_packages

setup(
    name="flaghound",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        
    ],
    entry_points={
        'console_scripts': [
            'flaghound=flaghound.cli:main',
        ],
    },
    author="0XIdl4n",
    description="An advanced CTF Triage and Quick-Strike automation tool.",
    python_requires='>=3.8',
)