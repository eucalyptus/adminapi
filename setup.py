#!/usr/bin/python

from setuptools import setup, find_packages

__version__ = '0.22'

setup(name="adminapi",
      version=__version__,
      description="Eucalyptus Cloud Services and General System Administrative Utilities",
      long_description="Eucalyptus Cloud Services and General System Administrative Utilities",
      url="https://github.com/bigschwan/adminapi",
      dependency_links = ['https://github.com/nephomaniac/python-midonetclient/tarball/4_3_0_e#egg=midonetclient'],
      install_requires=['paramiko >= 1.7',
                        'boto >= 2.5.2',
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
