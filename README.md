# adminapi

Eucalyptus Cloud Services and General System Administrative Utilities

See subdirectories for additional information:


Installation
------
A 'c' compiler may need to be installed beforehand (for Paramiko/ssh dependencies):
If pip/easy_install is not available in your environment use your package manager to
install python-setuptools as well:

    yum install python-setuptools gcc python-devel git
    apt-get install python-setuptools gcc python-dev git

Installing using pip or easy_install:

    pip install adminapi
    - or -
    easy_install adminapi


Installing from source:
For development purposes you can then clone the code from github, make changes, re-install, etc..

    git clone https://github.com/bigschwan/adminapi.git
    cd adminapi
    [Optional: CHANGE SOME CODE]
    sudo python setup.py install




Primary subdirectories:
------

### Cloud_utils modules:

    ##### file_utils
        File related helper utilities.

    ##### log_utils
        Utilties intended to help with logging, such as; creating loggers with sane defaults,
        formatting log output, helper methods and annotations for gathering debug, getting etc..

    ##### net_utils
        Network related utilities. Modules for creating connections such as ssh, sftp, winrm, etc..
        Utilities to help with network tests, gathering network information, etc..

    ##### system_utils
        Utilties to help with end machine/systems. Modules to aid in standard Linux system
    administrative tasks, etc..
    ##### cloud_admin:

### Cloud admin modules:

##### access:
    Utility modules related to Cloud Account's and cloud user's access to a cloud.
    Fetching/creating cloud credentials, Account, users, policies, etc..

##### backends:
    Cloud backend modules. This may include backend modules for:
        - Block storage modules for the backing HW or SW (ie SAN, DAS, Ceph, etc)
        - Network modules (ie: Network HW, SDN component interfaces, etc. )
        - Hypervisor modules (ie: vmware api, etc)
        - Object Storage modules (ie: Riak, etc)

##### hosts:
    Host machine modules. Utilities for the machines which host cloud services.
    This may include:
        - Eucalyptus Host machine modules and service specific machine helper modules. These will
          be primarily for Linux machines which are hosting the Eucalyptus services.
        - Utlities to manage the host machines.

##### services:
    Eucalyptus specific modules. Utilities to handle cloud services requests, and responses.
    This may include:
        - Eucalyptus Administrative Services
        - Eucalyptus Administrative Properties
        - Eucalyptus Administrative API

##### cloudview
    Eucalyptus Cloud topology utilities.
    This may include:
        - Utilities to help manage, monitor, debug a given topology.
        - Utilities to help deploy, configure, etc..
        - Utilities to help discovery, and create representations of a given topology
         in code and in different text or graphical formats.











