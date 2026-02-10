from setuptools import setup, find_packages

setup(
    name="east-scan",
    version="1.0.0",
    description="External Attack Surface Test (EAST) Automation Tool",
    packages=find_packages(),
    install_requires=[
        "python-docx>=0.8.11",
        "matplotlib>=3.7.0",
        "Pillow>=9.5.0",
        "requests>=2.31.0",
        "dnspython>=2.4.0",
        "validators>=0.22.0",
        "pyyaml>=6.0.1",
        "click>=8.1.0",
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "east-scan=east.cli:cli",
        ],
    },
    python_requires=">=3.10",
)
