#!/usr/bin/env python3
from setuptools import setup
from Cython.Build import cythonize


setup(
    ext_modules=cythonize(
        [
            'src/client/*.pyx',
            'src/server/stkey.pyx'
        ],
        language_level='3',
        #annotate=True,
    ),
    zip_safe=False,
)
