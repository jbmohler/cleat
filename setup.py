#!/usr/bin/env python

from distutils.core import setup

setup(
    name="cleat",
    version="0.1",
    description="build tool for server container farm",
    author="Joel B. Mohler",
    author_email="jmohler@kiwistrawberry.us",
    url="https://github.com/jbmohler/cleat",
    entry_points={"console_scripts": ["cleat=cleat:main"]},
    packages=["cleat"],
)
