from setuptools import setup, Extension

# Defina a extensão com informações sobre o arquivo C
rle_extension = Extension('rle', sources=['ext/rle.c'])

setup(
    name='rle',
    version='1.0.0',
    ext_modules=[rle_extension],
)
