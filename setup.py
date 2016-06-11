#!/usr/bin/python

from setuptools import setup, find_packages

__version__ = '0.22'

setup(name="adminapi",
      version=__version__,
      description="Eucalyptus Cloud Services and General System Administrative Utilities",
      long_description="Eucalyptus Cloud Services and General System Administrative Utilities",
      url="https://github.com/bigschwan/adminapi",
      install_requires=['paramiko >= 1.7',
                        'boto >= 2.5.2',
                        'argparse',
                        'pywinrm',
                        'requests >= 1',
                        'prettytable',
			            'python-dateutil',
                        'dnspython'],
      packages=find_packages(),
      license='BSD (Simplified)',
      platforms='Posix; MacOS X;',
      classifiers=['Development Status :: 3 - Alpha',
                   'Intended Audience :: System Administrators',
                   'Operating System :: OS Independent',
                   'Topic :: System :: Systems Administration'],
      )
