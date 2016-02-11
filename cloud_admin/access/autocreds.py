"""
AutoCreds is a convenience class which attempts to provide utilities for reading in
credentials data from multiple sources to build out a specific user's runtime configuration.
The auto_create flag (set to True by default) attempts  to automatically produce credentials
based upon the information provided to this AutoCreds obj.
        - If any ssh connect arguments (outside of hostname) are provided then only the remote
        machine tried for existing creds at 'self._credpath'.
        - If credpath was provided the local file system will first be tried for existing
        credentials
        - If aws access and secret keys were provided allong with hostname, will attempt to
        derive service credpaths from the Eucalyptus Admin api.
        -Finally if a hostname was provided an ssh attempt will be made (with any other
         connection kwargs provided)to fetch from the remote system as well.
         If password or keypath was not provided, this assumes keys have been sync'd between the
         localhost and the remote machine.
        Upon the first successful discovery of credentials, the local obj is populated with
        eucarc attributes and returns.

Some examples:
In [7]: from cloud_admin.access.autocreds import AutoCreds

# From a remote machine..
In [8]: creds = AutoCreds(credpath='', hostname='10.111.5.156', password='foobar')
In [9]: creds.ec2_url
Out[9]: 'http://10.111.5.156:8773/services/compute'

# From a local filepath:
In [11]: creds = AutoCreds(credpath='eucarc-10.111.5.156-eucalyptus-admin/eucarc')
In [12]: creds.s3_url
Out[12]: 'http://10.111.5.156:8773/services/objectstorage'

# Finally from the Eucalyptus Admin Api...
creds = AutoCreds(aws_access_key=aws_access_key, aws_secret_key=aws_secret_key,
                  hostname='10.111.5.156')

# Access the credential values as attributes of the AutoCreds obj such as:
In [21]: admin_connection = ServiceConnection(host='10.111.5.156',
                                              aws_access_key_id=creds.aws_access_key,
                                              aws_secret_key=creds.aws_secret_key)

# All creds can be fetched in a dict using:
In [22]: creds.get_eucarc_attrs()
Out[22]:
{'aws_access_key': 'AKIAAAI765C6PIO7QMS7',
 'aws_auto_scaling_url': 'http://10.111.5.156:8773/services/AutoScaling',
 'aws_cloudformation_url': 'http://10.111.5.156:8773/services/CloudFormation',
 'aws_cloudwatch_url': 'http://10.111.5.156:8773/services/CloudWatch',
 'aws_credential_file': None,
 'aws_elb_url': 'http://10.111.5.156:8773/services/LoadBalancing',
 'aws_iam_url': 'http://10.111.5.156:8773/services/Euare',
 'aws_secret_key': 'lqi6Bp6hHAIwkXwicRyDKxHDckr2vrnDd7I1xu6d',
 'aws_simpleworkflow_url': 'http://10.111.5.156:8773/services/SimpleWorkflow',
 'ec2_access_key': 'AKIAAAI765C6PIO7QMS7',
 'ec2_account_number': None,
 'ec2_cert': None,
 'ec2_jvm_args': None,
 'ec2_private_key': None,
 'ec2_secret_key': 'lqi6Bp6hHAIwkXwicRyDKxHDckr2vrnDd7I1xu6d',
 'ec2_url': 'http://10.111.5.156:8773/services/compute',
 'ec2_user_id': None,
 'euare_url': 'http://10.111.5.156:8773/services/Euare',
 'eucalyptus_cert': None,
 'eustore_url': 'http://emis.eucalyptus.com/',
 's3_url': 'http://10.111.5.156:8773/services/objectstorage',
 'token_url': 'http://10.111.5.156:8773/services/Tokens'}

 # For easy viewing, they can be shown in table format as well:
In [23]: creds.show()
[2015-05-18 15:47:12,249] [AutoCreds] [DEBUG]:
+------------------------+--------------------------------------------------+
| ec2_account_number     | None                                             |
+------------------------+--------------------------------------------------+
| euare_url              | http://10.111.5.156:8773/services/Euare          |
+------------------------+--------------------------------------------------+
| ec2_user_id            | None                                             |
+------------------------+--------------------------------------------------+
| token_url              | http://10.111.5.156:8773/services/Tokens         |
+------------------------+--------------------------------------------------+
| ec2_url                | http://10.111.5.156:8773/services/compute        |
+------------------------+--------------------------------------------------+
| aws_elb_url            | http://10.111.5.156:8773/services/LoadBalancing  |
+------------------------+--------------------------------------------------+
| aws_cloudformation_url | http://10.111.5.156:8773/services/CloudFormation |
+------------------------+--------------------------------------------------+
| aws_secret_key         | lqi6Bp6hHAIwkXwicRyDKxHDckr2vrnDd7I1xu6d         |
+------------------------+--------------------------------------------------+
| aws_cloudwatch_url     | http://10.111.5.156:8773/services/CloudWatch     |
+------------------------+--------------------------------------------------+
| eucalyptus_cert        | None                                             |
+------------------------+--------------------------------------------------+
| s3_url                 | http://10.111.5.156:8773/services/objectstorage  |
+------------------------+--------------------------------------------------+
| aws_iam_url            | http://10.111.5.156:8773/services/Euare          |
+------------------------+--------------------------------------------------+
| aws_simpleworkflow_url | http://10.111.5.156:8773/services/SimpleWorkflow |
+------------------------+--------------------------------------------------+
| ec2_jvm_args           | None                                             |
+------------------------+--------------------------------------------------+
| ec2_private_key        | None                                             |
+------------------------+--------------------------------------------------+
| ec2_access_key         | AKIAAAI765C6PIO7QMS7                             |
+------------------------+--------------------------------------------------+
| ec2_secret_key         | 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         |
+------------------------+--------------------------------------------------+
| aws_access_key         | AKIAAAI765C6PIO7QMS7                             |
+------------------------+--------------------------------------------------+
| eustore_url            | http://emis.eucalyptus.com/                      |
+------------------------+--------------------------------------------------+
| aws_credential_file    | None                                             |
+------------------------+--------------------------------------------------+
| ec2_cert               | None                                             |
+------------------------+--------------------------------------------------+
| aws_auto_scaling_url   | http://10.111.5.156:8773/services/AutoScaling    |
+------------------------+--------------------------------------------------+
| UNPARSED LINES         | None                                             |
+------------------------+--------------------------------------------------+)
"""
import errno
import os.path
import re
from StringIO import StringIO
import zipfile
from urlparse import urlparse
from cloud_utils.file_utils.eucarc import Eucarc
from cloud_utils.log_utils import get_traceback
from cloud_utils.system_utils.machine import Machine
from cloud_admin.services.serviceconnection import ServiceConnection
from cloud_utils.net_utils.sshconnection import CommandExitCodeException
from cloud_admin.hosts.eucahost import EucaHost


eucarc_to_service_map = {
    "euare_url": 'euare',
    "ec2_url": 'compute',
    "token_url": 'tokens',
    "aws_elb_url": 'loadbalancing',
    "aws_cloudformation_url": 'cloudformation',
    "aws_cloudwatch_url": 'cloudwatch',
    "s3_url": 'objectstorage',
    "aws_iam_url": 'euare',
    "aws_simpleworkflow_url": 'simpleworkflow',
    "aws_auto_scaling_url": 'autoscaling'}


class AutoCreds(Eucarc):
    def __init__(self,
                 auto_create=True,
                 aws_access_key=None,
                 aws_secret_key=None,
                 aws_account_name=None,
                 aws_user_name=None,
                 machine=None,
                 hostname=None,
                 username='root',
                 password=None,
                 keypath=None,
                 credpath=None,
                 proxy_hostname=None,
                 proxy_username='root',
                 proxy_password=None,
                 proxy_keypath=None,
                 logger=None,
                 log_level='INFO',
                 eucarc_obj=None,
                 existing_certs=True,
                 service_connection=None,
                 keysdir=None,
                 string=None,
                 clc_connect_kwargs=None):
        super(AutoCreds, self).__init__(logger=logger, loglevel=log_level)
        self._local_files = None
        self._serviceconnection = service_connection
        self._clc_ip = hostname
        self._string = string
        self._keysdir = keysdir
        self._machine = machine
        self._credpath = credpath
        self._account_name = aws_account_name
        self._user_name = aws_user_name
        self._has_existing_cert = existing_certs
        self.aws_secret_key = aws_secret_key
        self.aws_access_key = aws_access_key
        self._has_updated_connect_args = False  # used to speed up auto find credentials
        if (username != 'root' or proxy_username != 'root' or password or keypath or
                proxy_hostname or proxy_keypath or proxy_password):
            self._has_updated_connect_args = True
        clc_connect_kwargs = clc_connect_kwargs or {}
        self._clc_connect_kwargs = {
            'hostname': hostname,
            'username': username,
            'password': password,
            'keypath': keypath,
            'proxy_hostname': proxy_hostname,
            'proxy_username': proxy_username,
            'proxy_password': proxy_password,
            'proxy_keypath': proxy_keypath
        }
        self._clc_connect_kwargs.update(clc_connect_kwargs)
        if eucarc_obj:
            self.__dict__.update(eucarc_obj.__dict__)
        if not (self.aws_access_key and self.aws_secret_key) and auto_create:
            self.auto_find_credentials()

    @property
    def creds_machine(self):
        if not self._machine:
            self._machine = self.connect_to_creds_machine()
        return self._machine

    @creds_machine.setter
    def creds_machine(self, machine):
        self._machine = machine

    @property
    def serviceconnection(self):
        if not self._serviceconnection:
            self._serviceconnection = self._connect_services()
        return self._serviceconnection

    def _connect_services(self):
        if self.aws_secret_key and self.aws_access_key and self._clc_ip:
            self._serviceconnection = ServiceConnection(hostname=self._clc_ip,
                                                        aws_access_key=self.aws_access_key,
                                                        aws_secret_key=self.aws_secret_key)
        return self._serviceconnection

    def _close_adminpi(self):
        """
        If open, Attempts to close/cleanup the AutoCred's serviceconnection obj
        """
        if self._serviceconnection:
            try:
                self._serviceconnection.close()
                self._serviceconnection = None
            except:
                pass

    def update_attrs_from_cloud_services(self):
        """
        Attempts to update the current eucarc artifacts (service paths) from services
        gathered via the Eucalyptus admin api interface
        :returns dict mapping eucarc common key-values to the discovered service URIs.
        """
        if not self.serviceconnection:
            raise RuntimeError('Can not fetch service paths from cloud without an '
                               'ServiceConnection\n This requires: clc_ip, aws_access_key, '
                               'aws_secret_key')
        path_dict = self._get_service_paths_from_serviceconnection(self.serviceconnection)
        if not path_dict.get('ec2_access_key'):
            path_dict['ec2_access_key'] = self.aws_access_key
        if not path_dict.get('ec2_secret_key'):
            path_dict['ec2_secret_key'] = self.aws_secret_key
        for key, value in path_dict.iteritems():
            setattr(self, key, value)
        # self.__dict__.update(path_dict)
        #self._close_adminpi()
        return path_dict

    @classmethod
    def _get_service_paths_from_serviceconnection(cls, serviceconnection):
        """
        Reads the Eucalyptus services, maps them to common eucarc key values, and returns
        the dict of the mapping.
        :params serviceconnection: an ServiceConnection obj w/ active connection.
        :returns dict mapping eucarc common key-values to the discovered service URIs.
        """
        assert isinstance(serviceconnection, ServiceConnection)
        services = serviceconnection.get_services()
        ret_dict = {}
        for service in services:
            for key, serv_value in eucarc_to_service_map.iteritems():
                if service.type == serv_value:
                    ret_dict[key] = str(service.uri)
        return ret_dict

    def get_local_eucarc(self, credpath):
        """
        Reads in eucarc contents from a local file path. Checks to make sure the credpath
        given is an existing file, if a dir was provide it will check for a file name 'eucarc'
        in that dir.
        :params credpath: string representing the path to the eucarc file
        :return dict of eucarc read in
        """
        if not str(credpath).endswith('eucarc') and os.path.isdir(credpath):
            credpath = os.path.join(credpath, 'eucarc')
        if os.path.isfile(credpath):
            return self._from_filepath(credpath)
        return None

    def get_remote_eucarc(self, credpath, machine=None):
        """
        Reads in eucarc contents from a remote file path on the provided Machine().
        Checks to make sure the credpath given is an existing file, if a dir was provide it will
        check for a file name 'eucarc' in that dir.
        :params credpath: string representing the path to the eucarc file
        :params machine: Machine() obj
        :returns dict of eucarc read in
        """
        machine = machine or self.creds_machine
        if not str(credpath).endswith('eucarc') and machine.is_dir(credpath):
            credpath = os.path.join(credpath, 'eucarc')
        if machine.is_file(credpath):
            return self._from_filepath(filepath=credpath, sshconnection=machine._ssh)
        return None

    def connect_to_creds_machine(self, connect_kwargs=None):
        """
        Attempts to create a Machine by connecting to the remote host, usually the CLC.
        :params connect_kwargs: Dictionary set of arguments to be provided to Machine().__init__()
        returns machine obj upon success
        """
        connect_kwargs = connect_kwargs or self._clc_connect_kwargs
        machine = Machine(**connect_kwargs)
        self.creds_machine = machine
        return machine

    def assume_role_on_remote_clc(self, machine=None):
        machine = machine or self.creds_machine
        cred_string = []
        out = machine.sys('clcadmin-assume-system-credentials', code=0)
        for line in out:
            if line:
                line = line.strip(';')
            line = str(line).replace('127.0.0.1', machine.hostname)
            cred_string.append(line)
        return self._from_string(string=cred_string)


    def auto_find_credentials(self, from_file=True, assume_admin=True, service_connection=True,
                              from_remote=True, from_db=True):
        """
        Convenience method which attempts to automatically produce credentials based upon the
        information provided to this AutoCreds obj.
        - If any ssh connect arguments (outside of hostname) are provided then only the remote
        machine tried for existing creds at 'self._credpath'.
        - If credpath was provided the local file system will first be tried for existing
        credentials
        - If aws access and secret keys were provided allong with hostname, will attempt to
        derivce service credpaths from the Eucalyptus Admin api.
        -Finally if a hostname was provided an ssh attempt will be made (with any other
         connection kwargs provided)to fetch from the remote system as well.
         If password or keypath was not provided, this assumes keys have been sync'd between the
         localhost and the remote machine.
        Upon the first successful discovery of credentials, the local obj is populated with
        eucarc attributes and returns.
        """

        def try_from_file(self):
            self.log.debug('Trying creds from local file...')
            if self._credpath:
                try:
                    res = self.get_local_eucarc(credpath=self._credpath)
                    if res:
                        self.log.debug('Found local creds at: "{0}"'.format(self._credpath))
                        return res
                except IOError:
                    pass

        def try_serviceconnection(self):
            self.log.debug('Trying creds from service connection...')
            if self.aws_secret_key and self.aws_access_key and self._clc_ip:
                self._connect_services()
                try:
                    res = self.update_attrs_from_cloud_services()
                    if res:
                        self.log.debug('Derived creds from serviceconnection')
                        return res
                except RuntimeError as RE:
                    self.log.debug('{0}\nFailed to update creds using serviceconnection, err:"{1}"'
                               .format(get_traceback(), str(RE)))
                    self._close_adminpi()

        def try_assume_admin_on_clc(self):
            self.log.debug('Trying creds from assume admin role on clc...')
            if not self.aws_secret_key and not self.aws_access_key:
                try:
                    self.assume_role_on_remote_clc()
                    res = try_serviceconnection(self)
                    try:
                        # With keys, try filling in remainder with service urls/attributes
                        # using the admin api interface...
                        res = self.update_attrs_from_cloud_services()
                    except:
                        pass
                    return res
                except Exception as AE:
                    self.log.debug('{0}\nFailed to update creds using '
                               '"clcadmin-assume-system-credentials", err:"{1}"'
                               .format(get_traceback(), str(AE)))

        def try_remote(self):
            self.log.debug('Trying creds from remote machine at credpath...')
            if self.creds_machine and self._credpath:
                try:
                    machine = self.creds_machine or self.connect_to_creds_machine()
                    if machine:
                        try:
                            if not self._keysdir:
                                self._keysdir = machine.get_abs_path(self._credpath)
                        except:
                            pass
                        res = self.get_remote_eucarc(credpath=self._credpath, machine=machine)
                        if res:
                            self.log.debug('Found remote creds on:"{0}", at path:"{1}"'
                                       .format(self.creds_machine.ssh.host, self._credpath))
                            return res
                except Exception as e:
                    self.log.debug("{0}\nFailed to fetch creds remotely, err:'{1}'"
                               .format(get_traceback(), str(e)))

        def try_clc_db(self):
            self.log.debug('Trying creds from CLC DB...')
            if self.creds_machine and self.aws_account_name and self.aws_user_name:
                machine = self.creds_machine or self.connect_to_creds_machine()
                if machine:
                    try:
                        res = self.get_existing_keys_from_clc(account=self.aws_account_name,
                                                              user=self.aws_user_name,
                                                              machine=machine)
                        try:
                            # With keys, try filling in remainder with service urls/attributes
                            # using the admin api interface...
                            res = self.update_attrs_from_cloud_services()
                        except:
                            pass
                        return res
                    except RuntimeError as RE:
                        self.log.debug('{0}\nFailed to fetch creds from clc db, err:{1}'
                                   .format(get_traceback(), str(RE)))

        default_order = []
        if from_file:
            default_order.append(try_from_file)
        if service_connection:
            default_order.append(try_serviceconnection)
        if assume_admin:
            default_order.append(try_assume_admin_on_clc)
        if from_remote:
            default_order.append(try_remote)
        if from_db:
            default_order.append(try_clc_db)
        if self._clc_ip and self._credpath and \
                (self._has_updated_connect_args or self._sshconnection):
            # if any ssh related arguements were provided, assume the user would like
            # to try remote first
            if try_remote(self):
                return
            default_order.remove(try_remote)
            raise ValueError('Could not find "remote" creds with provided information.')
        else:
            for meth in default_order:
                if meth(self):
                    return
            raise ValueError("Could not find path with provided information.")


    def get_existing_keys_from_clc(self, account, user, machine=None, eucahome=None, port=8777,
                                   dbuser='eucalyptus', p12file=None, pkfile=None,
                                   passphrase=None, db=None, pargs=None, do_cert=None,
                                   verbose=False):
        ret = {}
        db = db or 'eucalyptus_shared'
        pargs = pargs or ""
        machine = machine or self.creds_machine
        passphrase = None or 'eucalyptus'
        if do_cert is None:
            do_cert = self._has_existing_cert
        if hasattr(machine, 'eucalyptus_home'):
            eucahome = machine.eucalyptus_home
        else:
            eucahome = eucahome or EucaHost._get_eucalyptus_home(machine) or '/'
        EucaP12File = p12file or os.path.join(eucahome, '/var/lib/eucalyptus/keys/euca.p12')
        CloudPKFile = pkfile or os.path.join(eucahome, '/var/lib/eucalyptus/keys/cloud-pk.pem')
        cmd = ("echo -n '{0}' | openssl SHA256  -sign {1} | sha256sum"
               .format(passphrase, CloudPKFile))
        out = machine.sys(cmd, code=0, verbose=verbose)
        if out:
            dbpass = str(out[0]).split()[0]

        if do_cert:
            dbsel = ("\"select k.auth_access_key_query_id, k.auth_access_key_key, "
                     "a.auth_account_number, a.auth_account_name, c.auth_certificate_pem "
                     "from eucalyptus_auth.auth_access_key k "
                     "join eucalyptus_auth.auth_user u on k.auth_access_key_owning_user=u.id "
                     "join eucalyptus_auth.auth_cert c on c.auth_certificate_owning_user=u.id "
                     "join eucalyptus_auth.auth_group_has_users gu on gu.auth_user_id = u.id "
                     "join eucalyptus_auth.auth_group g on gu.auth_group_id=g.id "
                     "join eucalyptus_auth.auth_account a on g.auth_group_owning_account=a.id "
                     "where a.auth_account_name = '{0}' and g.auth_group_name = '{1}'\";"
                     .format(account, "_" + user))
        else:
            dbsel = ("\"select k.auth_access_key_query_id, k.auth_access_key_key, "
                     "a.auth_account_number, a.auth_account_name "
                     "from eucalyptus_auth.auth_access_key k "
                     "join eucalyptus_auth.auth_user u on k.auth_access_key_owning_user=u.id "
                     "join eucalyptus_auth.auth_group_has_users gu on gu.auth_user_id = u.id "
                     "join eucalyptus_auth.auth_group g on gu.auth_group_id=g.id "
                     "join eucalyptus_auth.auth_account a on g.auth_group_owning_account=a.id "
                     "where a.auth_account_name = '{0}' and g.auth_group_name = '{1}'\";"
                     .format(account, "_" + user))
        dbcmd = ('export PGPASSWORD={0}; psql {1} -A -F "," -h 127.0.0.1 -p {2} -U {3} -d {4} '
                 '-c {5}'.format(dbpass, pargs, port, dbuser, db, dbsel))
        qout = machine.sys(dbcmd, code=0, verbose=verbose)
        if verbose:
                self.log.info('Result of cmd:"{0}"\n"{1}"'.format(dbcmd, qout))
        if qout:
            try:
                names = qout[0].split(',')
                values = qout[1].split(',')
                ret['AWS_ACCESS_KEY'] = values[names.index('auth_access_key_query_id')]
                ret['AWS_SECRET_KEY'] = values[names.index('auth_access_key_key')]
                ret['EC2_ACCOUNT_NUMBER'] = values[names.index('auth_account_number')]
                ret['EC2_ACCOUNT_NAME'] = values[names.index('auth_account_name')]
                if do_cert:
                    ret['CERT'] = values[names.index('auth_certificate_pem')]
                self.aws_access_key = ret['AWS_ACCESS_KEY']
                self.aws_secret_key = ret['AWS_SECRET_KEY']
                self.ec2_user_id = ret['EC2_ACCOUNT_NUMBER']
                self.ec2_account_number = ret['EC2_ACCOUNT_NUMBER']
                self.ec2_account_name = ret['EC2_ACCOUNT_NAME']
            except Exception as PE:
                self.log.error('{0}\nOutput:\nFailed fetching existing creds for account:"{1}", '
                               'user:"{2}".\nRemote Command Output:"{3}"'
                               .format(get_traceback(), account, user, "\n".join(qout), str(PE)))
                raise PE
        return ret

    def create_local_creds(self, local_destdir, machine=None, keydir=None, overwrite=False,
                           zipfilename=None, ziponly=False):
        """
        Attempts to create a local set of files containing the current credential artifacts
        in this AutoCreds obj. The following files will be written to the provided
        'local_destdir' directory:
        - A eucarc file containing the "export key=value" syntax to resolve service urls
          and the location of any credentials related files.
        - Any current attributes with an sftp:// uri will be downloaded to local_destdir. At this
        time the AutoCred eucarc attributes will be updated to represent their now local filepath,
        an the local eucarc written will also reflect the new location.

        :param local_destdir: local directory to write cred files to.
                               Will create if does not exist.
        :param machine: The Machine() obj to download any sftp:// files from
        :param keydir: optional String representing path to key dir, otherwise auto-populated
        :param overwrite: bool, if True will overwrite any existing items at 'local_destdir'
        :param zipfilename: string representing the zip archive filename to be creat in the
                            'local_destdir' directory. If "None" a zip archive will not be created.
        :param ziponly: boolean, if true only a zip archive will be created
        :return: list of filepaths
        """
        def make_local_dir(dirpath):
            if dirpath:
                try:
                    os.makedirs(dirpath)
                except OSError as exc:
                    if exc.errno == errno.EEXIST and os.path.isdir(dirpath):
                        pass
                    else:
                        raise


        filepaths = []
        local_destdir = os.path.abspath(local_destdir or "")
        if zipfilename:
            make_local_dir(local_destdir)
            zip_path = os.path.join(local_destdir, zipfilename)
            if os.path.exists(zip_path):
                raise ValueError('Will not overwrite existing credentials archive at:"{0}"'
                                 .format(zip_path))
            zip_file = zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED, False)
        else:
            zip_file = None
        machine = machine or self.creds_machine
        if keydir is None:
            keydir = "EUCA_KEY_DIR=$(cd $(dirname ${BASH_SOURCE:-$0}); pwd -P)"
        has_sftp_items = False

        for key, value in self.get_eucarc_attrs().iteritems():
            if isinstance(value, basestring) and re.search('^sftp://', value):
                has_sftp_items = True
        if has_sftp_items:
            if not machine:
                if not self._has_updated_connect_args:
                    self.log.info('Remote machine info has not been provided, '
                                  'skipping remote creds download')
                else:
                    machine = self.connect_to_creds_machine()
            if zip_file and ziponly:
                filepaths = self._download_remote_artifacts(local_destdir=None,
                                                            machine=machine,
                                                            overwrite=overwrite,
                                                            zip_file=zip_file)
            else:
                filepaths = self._download_remote_artifacts(local_destdir=local_destdir,
                                                            machine=machine,
                                                            overwrite=overwrite)
        if zip_file and ziponly:
            if self.serviceconnection is not None:
                certs = self.serviceconnection.get_service_certs()
                if not certs:
                    raise ValueError('No service certs found in DescribeServiceCerts response')
                cert = certs[0]
                certbody = cert.certificate
                if not certbody:
                    raise ValueError('Certbody not found in retrieved cert')
                zip_file.writestr('cloud-cert.pem', certbody)
            eucarc = ""

            eucarc += keydir + "\n"
            for key, value in self.get_eucarc_attrs().iteritems():
                if isinstance(value, basestring) and not re.search('^sftp://', value):
                    eucarc += 'export {0}="{1}";\n'.format(str(key).upper(), value)
            zip_file.writestr('eucarc', eucarc)
            zip_file.close()
            filepaths.append(zipfilename)
        else:
            # Now write the eucarc file. Any downloaded files should have updated the
            # local euarc attrs replacing the sftp uri with a local file path
            make_local_dir(local_destdir)
            cloud_cert_path = os.path.join(local_destdir, 'cloud-cert.pem')
            if os.path.exists(cloud_cert_path):
                filepaths.append(cloud_cert_path)
            elif self.serviceconnection is not None:
                self.serviceconnection.write_service_cert_to_file(cloud_cert_path)
                filepaths.append(cloud_cert_path)
            eucarc_path = os.path.join(local_destdir, 'eucarc')
            filepaths.append(eucarc_path)
            with open(eucarc_path, 'w') as eucarc:
                eucarc.seek(0)
                eucarc.write(keydir + "\n")
                for key, value in self.get_eucarc_attrs().iteritems():
                    if isinstance(value, basestring) and not re.search('^sftp://', value):
                        eucarc.write('export {0}="{1}";\n'.format(str(key).upper(), value))
                eucarc.flush()
            self.log.debug('Finished creating new local creds at: {0}'.format(local_destdir))
            self._local_files = filepaths
            if zip_file:
                for path in filepaths:
                    fname = os.path.basename(path)
                    zip_file.write(path, fname)
                zip_file.close()
                filepaths.append(zipfilename)
        return filepaths

    def _download_remote_artifacts(self, local_destdir, machine, zip_file=None,
                                   sftp_prefix='^sftp://', overwrite=False, maxlen=5000000):
        """
        Attempts to download any eucarc artifacts which current has an sftp:// url.
        To see these values use self.show() or self.get_eucarc_attrs() dict.
        :params local_destdir: Local directory to download the remote files to
        :params machine: remote machine object to download the files from
        :params sftp_prefeix: The search criteria for determining which eucarc artifacts
                              should be downloaded.
        :params overwrite: bool, if True will overwrite any existing items at 'local_destdir'
        returns list. The local paths (strings) items were downloaded to upon success
        """
        filepaths = []
        if not isinstance(machine, Machine):
            raise ValueError('_download_remote_artifacts requires Machine() type. Got:"{0}/{1}"'
                             .format(machine, type(machine)))
        if zip_file is not None:
            if not isinstance(zip_file, zipfile.ZipFile):
                raise TypeError('zip_file must be of type ZipFile, got:"{0}/{1}"'
                                .format(zipfile, type(zipfile)))
            if local_destdir is not None:
                raise ValueError('local_destdir must be None if providing a zipfile')
        elif not isinstance(local_destdir, basestring):
            raise ValueError('_download_remote_artifacts requires string for local_destdir(). '
                             'Got:"{0}/{1}"'.format(local_destdir, type(local_destdir)))
        if not os.path.exists(local_destdir):
            os.makedirs(local_destdir)
        else:
            if not os.path.isdir(local_destdir):
                raise ValueError('Provided local_destdir exists and is not a directory:"{0}"'
                                 .format(local_destdir))
            if not overwrite:
                raise ValueError('local_destdir exists. set "overwrite=True" to write over '
                                 'existing contents: {0}'.format(local_destdir))
        if local_destdir is not None:
            local_destdir = os.path.abspath(local_destdir)
        for key, path in self.get_eucarc_attrs().iteritems():
            if not key.startswith('_') and re.search(sftp_prefix, str(path)):
                urlp = urlparse(path)
                if not self.creds_machine.hostname == urlp.hostname:
                    raise ValueError('sftp uri hostname:{0} does not match current Machines:{1}'
                                     .format(urlp.hostname, machine.hostname))
                artifact_name = os.path.basename(urlp.path)
                if local_destdir is not None:
                    localpath = os.path.join(local_destdir, artifact_name)
                    machine.sftp.get(remotepath=urlp.path, localpath=localpath)
                    self.log.debug('Wrote: {0} to local:{1}'.format(key, localpath))
                elif zip_file:
                    with machine.sftp.open(urlp.path) as remote_file:
                        data = remote_file.read(maxlen)
                    zip_file.writestr(artifact_name, data)
                    self.log.debug('Wrote: {0} to zipfile object'.format(key))
                filepaths.append(localpath)
                setattr(self, key, localpath)
        return filepaths
