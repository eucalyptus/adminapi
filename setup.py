#!/usr/bin/python

from setuptools import setup, find_packages

__version__ = '1.4.3.0.1.1'

setup(name="adminapi",
      version=__version__,
      description="Eucalyptus Cloud Services and General System Administrative Utilities",
      long_description="Eucalyptus Cloud Services and General System Administrative Utilities",
      url="https://github.com/eucalyptus/adminapi",
      dependency_links = ['https://github.com/nephomaniac/python-midonetclient/tarball/4_3_0_e#egg=midonetclient'],
      install_requires=['paramiko >= 2.0.2',
                        'boto >= 2.5.2',
                        'isodate',
                        'argparse',
                        'kazoo',
                        'pywinrm',
                        'requests >= 1',
                        'prettytable',
                        'python-dateutil',
                        'dnspython',
                        'midonetclient'], 
      packages=find_packages(),
      license='BSD (Simplified)',
      platforms='Posix; MacOS X;',
      classifiers=['Development Status :: 3 - Alpha',
                   'Intended Audience :: System Administrators',
                   'Operating System :: OS Independent',
                   'Topic :: System :: Systems Administration'],
      )
