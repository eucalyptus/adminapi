
## Cloud_utils modules:

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


