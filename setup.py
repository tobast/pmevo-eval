#!/usr/bin/env python3

from setuptools import setup, find_packages
import sys

setup(
    name="pmevo_eval",
    version="0.0.1",
    description="Python interface to evaluate PMEvo",
    author="PMEvo team",
    license="LICENSE",
    url="https://github.com/tobast/pmevo-eval",
    packages=find_packages(),
    #    package_data={
    #        "": [
    #            "data/SKL/mapping_pmevo.json",
    #        ],
    #    },
    include_package_data=True,
    long_description=open("README.md").read(),
    install_requires=[],
)
