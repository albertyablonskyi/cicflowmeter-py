# -*- coding: utf-8 -*-

import io
import os
import importlib
from setuptools import find_packages, setup

# Package meta-data.
NAME = "cicflowmeter"
DESCRIPTION = "CICFlowMeter Early Edition Python Implementation"
URL = "https://gitlab.abo.fi/tahmad/cicflowmeter"
EMAIL = "tahmad@abo.fi"
AUTHOR = "Tanwir Ahmad"
REQUIRES_PYTHON = ">=3.7.0"
VERSION = None


def get_requirements(source: str = "requirements.txt"):
    requirements = []
    with open(source) as f:
        for line in f:
            package, _, comment = line.partition("#")
            package = package.strip()
            if package:
                requirements.append(package)

    return requirements


REQUIRED = get_requirements("requirements.txt")

# The rest you shouldn't have to touch too much :)
# ------------------------------------------------
# Except, perhaps the License and Trove Classifiers!
# If you do change the License, remember to change the Trove Classifier for that!

here = os.path.abspath(os.path.dirname(__file__))

# Import the README and use it as the long-description.
# Note: this will only work if 'README.md' is present in your MANIFEST.in file!
try:
    with io.open(os.path.join(here, "README.md"), encoding="utf-8") as f:
        long_description = "\n" + f.read()
except FileNotFoundError:
    long_description = DESCRIPTION

# Load the package's __version__.py module as a dictionary.
# if not VERSION:
#     project_slug = NAME.lower().replace("-", "_").replace(" ", "_")
#     about = importlib.import_module(project_slug)
#     VERSION = about.__version__

# Where the magic happens:
setup(
    name=NAME,
    version=__import__('cicflowmeter').__version__,
    description=DESCRIPTION,
    long_description=long_description,
    long_description_content_type="text/markdown",
    author=AUTHOR,
    author_email=EMAIL,
    python_requires=REQUIRES_PYTHON,
    url=URL,
    packages=find_packages(),
    # package_dir={"cicflowmeter": "src/cicflowmeter"},
    # package_dir={"": "cicflowmeter"},
    entry_points={
        "console_scripts": ["cicflowmeter=cicflowmeter.sniffer:main"],
    },
    install_requires=REQUIRED,
    include_package_data=True,
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
    ],
)
