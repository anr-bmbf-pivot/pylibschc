#!/usr/bin/env python3

# Copyright (C) 2023 Freie Universität Berlin
#
# SPDX-License-Identifier: GPL-3.0-only

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
        from Cython.Build import cythonize

        self.distribution.ext_modules = cythonize(
            self.distribution.ext_modules,
            language_level=3,
        )
        for e in self.distribution.ext_modules:
            if not hasattr(e, "cython_directives"):
                e.cython_directives = {}
            if bool(os.environ.get("CYTHON_EMBEDSIGNATURE", "0")):
                e.cython_directives["embedsignature"] = True


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
        "Development Status :: 4 - Beta",
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
    setup_requires=["setuptools>=42", "Cython", "wheel"],
    install_requires=list(get_requirements()),
    cmdclass={"build": Build},
    ext_modules=[
        Extension(
            "pylibschc.libschc",
            [
                "pylibschc/libschc.pyx",
                "src/pylogging.c",
                "src/rules.c",
                "src/libschc/bit_operations.c",
                "src/libschc/compressor.c",
                "src/libschc/fragmenter.c",
                "src/libschc/jsmn.c",
                "src/libschc/picocoap.c",
                "src/libschc/schc.c",
            ],
            include_dirs=["src/libschc", "src", "pylibschc"],
            extra_compile_args=["-Wno-unused-variable"],
            define_macros=[],
        ),
    ],
    python_requires=">=3.7",
)
