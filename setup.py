import sys
import subprocess

from distutils.core import setup, Command


setup(name='nixops-hetzner',
      version='@version@',
      description='NixOS cloud deployment tool, but for hetzner',
      url='https://github.com/NixOS/nixops-hetzner',
      # TODO: add author
      author='',
      author_email='',
      packages=[ 'nixopshetzner', 'nixopshetzner.backends'],
      entry_points={'nixops': ['hetzner = nixopshetzner.plugin']},
      py_modules=['plugin']
)
