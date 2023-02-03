#!/usr/bin/env python3

import os

from distutils.command.build import build
from setuptools import setup, find_packages, Extension

PACKAGE = "pylibschc"
URL = "https://github.com/anr-bmbf-pivot/pylibschc"
LICENSE = "GPLv3"


def get_requirements():
    with open("requirements.txt", encoding="utf-8") as req_file:
        for line in req_file:
            yield line.strip()


def get_version(package):
    """Extract package version without importing file
    Importing cause issues with coverage,
        (modules can be removed from sys.modules to prevent this)
    Importing __init__.py triggers importing rest and then requests too

    Inspired from pep8 setup.py
    """
    with open(os.path.join(package, "__init__.py"), encoding="utf-8") as init_fd:
        for line in init_fd:
            if line.startswith("__version__"):
                return eval(line.split("=")[-1])  # pylint:disable=eval-used
    return None


class Build(build):
    def finalize_options(self):
        super().finalize_options()


setup(
    name=PACKAGE,
    version=get_version(PACKAGE),
    description=f"{PACKAGE} - A python wrapper for libSCHC",
    long_description=open("README.rst").read(),
    long_description_content_type="text/x-rst",
    author="Martine S. Lenders",
    author_email="m.lenders@fu-berlin.de",
    license=LICENSE,
    url=URL,
    download_url=URL,
    packages=find_packages(exclude=["env", "*.tests", "*.tests.*", "tests.*", "tests"]),
    package_data={PACKAGE: ["pylibschc/clibschc.pxd"]},
    classifiers=[
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
    ],
    setup_requires=["setuptools>=42", "wheel"],
    install_requires=list(get_requirements()),
    cmdclass={"build": Build},
    python_requires=">=3.7",
)
