"""
Setup script for IDE Viewer.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read requirements
requirements = []
req_file = Path(__file__).parent / "requirements.txt"
if req_file.exists():
    requirements = [
        line.strip()
        for line in req_file.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]

# Read README
readme = ""
readme_file = Path(__file__).parent / "README.md"
if readme_file.exists():
    readme = readme_file.read_text()

setup(
    name="ideviewer",
    version="0.1.0",
    author="Securient",
    description="Cross-platform IDE and Extension Scanner Daemon",
    long_description=readme,
    long_description_content_type="text/markdown",
    license="PolyForm Noncommercial 1.0.0",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "schedule>=1.2.0",
        "watchdog>=3.0.0",
        "psutil>=5.9.0",
        "pyyaml>=6.0",
        "rich>=13.0.0",
        "click>=8.1.0",
    ],
    extras_require={
        "windows": ["pywin32>=306"],
        "dev": ["pytest>=7.0.0", "pytest-cov>=4.0.0"],
    },
    entry_points={
        "console_scripts": [
            "ideviewer=ideviewer.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: Other/Proprietary License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Software Development :: Build Tools",
        "Topic :: System :: Monitoring",
    ],
)
