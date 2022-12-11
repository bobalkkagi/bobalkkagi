from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    longDescription = fh.read()

setup(
    name="Bobalkkagi",
    version="0.1.0",
    author="Bobalkkagi",
    author_email="gkswlgns21@gmail.com",
    description="Unpack and UnWrapping executables protected with Themida 3.1.3",
    longDescription=longDescription,
    longDescription_content_type="text/markdown",
    url="https://github.com/hackerhoon/Bobalkkagi",
    project_urls={
        "updates": "https://github.com/hackerhoon/Bobalkkagi/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    package_dir={"": "Bobalkkagi"},
    packages=find_packages(where="Bobalkkagi"),
    python_requires=">=3.9",
)