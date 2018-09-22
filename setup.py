#!/usr/bin/env python3
import os
from setuptools import setup, find_packages


setup(
    name="netflow_exporter",
    version="0.1",
    packages=find_packages(),
    description="Netflow exporter and API server",
    author="Andy Foston",
    email="andy@foston.me",
    scripts=[os.path.join("netflow", "netflow_exporter.py")]
)