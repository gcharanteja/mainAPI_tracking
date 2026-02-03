from setuptools import setup, find_packages

setup(
    name="pck67_pkg",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31.0",
    ],
    entry_points={
        'console_scripts': [
            'pck67=pck67_pkg.cli:main',  # This creates the 'pck67' command
        ],
    },
    author="Charan",
    description="ML Experiment Tracking SDK",
    python_requires='>=3.8',
)