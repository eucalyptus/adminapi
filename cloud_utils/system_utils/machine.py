

import select
import threading
import time
from cloud_utils.log_utils.eulogger import Eulogger
from cloud_utils.log_utils import get_traceback
from cloud_utils.log_utils import printinfo, markup
from cloud_utils.file_utils import render_file_template
from cloud_utils.net_utils import test_port_status, get_network_info_for_cidr
from cloud_utils.net_utils.sshconnection import (
    CommandExitCodeException,
    SshCbReturn,
    SshConnection
)
import re
import os
from prettytable import PrettyTable
from socket import error as socketerror
import sys
import tempfile
from repoutils import Yum, Apt


class Machine(object):

    def __init__(self,
                 hostname,
                 username="root",
                 password=None,
                 keypath=None,
                 sshconnection=None,
                 proxy_hostname=None,
                 proxy_username='root',
                 proxy_password=None,
                 proxy_keypath=None,
                 do_ssh_connect=True,
                 distro=None,
                 distro_ver=None,
                 arch=None,
                 timeout=120,
                 ssh_retry=2,
                 logger=None,
                 log_level='INFO',
                 verbose=True):
        """
        A basic (primarily Linux) Machine interface. This interface is intended to provide a
        base set of utilities for working with a Linux machine in a Cloud system environment.
        The class is intended to be built upon adding more pointed utlities for VMs,
        Cloud components, etc..
        By default init() will attempt to create an sshconnection using the parameters provided.
        The primary method for interacting with the ssh session will be the machine.sys() method.
        Most utiltiy methods within this class are wrapping the sys() method and issuing common
        linux commands on the remote machine.

        :param hostname: The hostname or IP of the machine
        :param username: The ssh username used to for ssh login
        :param password: The password associate with 'username'
        :param keypath:  The path to an ssh key to be used, (defaults to the usual local key dirs)
        :param proxy_hostname: (optional) A ssh proxy hostname or ip
        :param proxy_username: (optional) Proxy username for ssh login
        :param proxy_password: (optional) Proxy password associated with proxy username
        :param proxy_keypath: (optional) ssh key path, otherwise will try the default ssh dir(s)
        :param do_ssh_connect: (optional) bool, if True will attempt an ssh connection.
        :param distro: (optional), string for distro name, otherwise will try to find it
        :param distro_ver: (optional) string for distro version, otherwise will try to find it
        :param arch: (optional) string for arch type, otherwise will try to find it
        :param timeout: (optional) time in seconds to allow for ssh connection to complete
        :param ssh_retry: (optional) int, number of ssh connection attempts
        :param debugmethod: (optional) A method used for writing debug information
        :param verbose: bool option to enable/disable some verbose logging
        """
        self._arch = arch
        self._ssh = sshconnection
        self._sftp = None
        self._distroname = distro
        self._distrover = distro_ver
        self._repo_utils = None
        self._package_manager = None
        self._config = None
        self._free_stats = {}
        self._cpu_stats = {}
        self._net_iface_stats = {}
        self._sys_stats_interval = 5
        self._hostname = hostname
        self.arch = arch
        self._do_ssh_connect = do_ssh_connect
        self.username = username
        self.password = password
        self.verbose = verbose
        if logger is None:
            logger = Eulogger(identifier=self._identifier, stdout_level=log_level)
        self.log = logger
        self.ssh_connect_kwargs = {'host': self.hostname,
                                   'username': self.username,
                                   'password': self.password,
                                   'keypath': keypath,
                                   'proxy': proxy_hostname,
                                   'proxy_username': proxy_username,
                                   'proxy_password': proxy_password,
                                   'proxy_keypath': proxy_keypath,
                                   'timeout': timeout,
                                   'retry': ssh_retry,
                                   'logger': self.log,
                                   'verbose': self.verbose
                                   }
        self.log_threads = {}
        self.log_buffers = {}
        self.log_active = {}
        self.wget_last_status = 0
        self.machine_setup()

    def machine_setup(self):
        # For custom implementations
        pass

    def __repr__(self):
        return "{0}:{1}".format(self.__class__.__name__, self.hostname)

    @property
    def hostname(self):
        if hasattr(self, 'ip_address'):
            return self.ip_address
        if hasattr(self, '_hostname'):
            return self._hostname
        return None

    @hostname.setter
    def hostname(self, hostname):
        if self.hostname and self.hostname != hostname:
            if self.ssh and self.ssh.host != hostname:
                self.log.debug('Hostname change from {0} -> {1}, setting self.ssh to None'
                               .format(self.hostname, hostname))
                self.ssh = None
        self._hostname = hostname

    @property
    def _identifier(self):
        return str(self.hostname or self.__class__)

    #############################################################################################
    #                       Debug Utilities                                                     #
    #############################################################################################

    def debug(self, msg):
        """
        Note: Should use self.log.debug instead.
        Used to print debug, defaults to print() but over ridden by self.debugmethod if not None
        msg - mandatory -string, message to be printed
        """
        if self.verbose is True:
            self.log.debug(msg)

    def poll_log(self, log_file="/var/log/messages"):
        self.log.debug("Starting to poll " + log_file)
        self.log_channel = self.ssh.connection.invoke_shell()
        self.log_channel.send("tail -f " + log_file + " \n")
        # Begin polling channel for any new data
        while self.log_active[log_file]:
            # CLOUD LOG
            rl, wl, xl = select.select([self.log_channel], [], [], 0.0)
            if len(rl) > 0:
                self.log_buffers[log_file] += self.log_channel.recv(1024)
            time.sleep(1)

    def start_log(self, log_file="/var/log/messages"):
        """Start thread to poll logs"""
        thread = threading.Thread(target=self.poll_log, args=log_file)
        thread.daemon = True
        self.log_threads[log_file] = thread.start()
        self.log_active[log_file] = True

    def stop_log(self, log_file="/var/log/messages"):
        """Terminate thread that is polling logs"""
        self.log_active[log_file] = False

    def save_log(self, log_file, path="logs"):
        """Save log buffer for log_file to the path to a file"""
        if not os.path.exists(path):
            os.mkdir(path)
        FILE = open(path + '/' + log_file, "w")
        FILE.writelines(self.log_buffers[log_file])
        FILE.close()

    def save_all_logs(self, path="logs"):
        """Save log buffers to a file"""
        for log_file in self.log_buffers.keys():
            self.save_log(log_file, path)

    def dump_netfail_info(self, ip=None, mac=None, pass1=None, pass2=None, showpass=True,
                          taillength=50, net_namespace=None, loglevel='debug'):
        """
        Debug method to provide potentially helpful info from current machine when debugging
        connectivity issues.
        :param ip: optional ip for ping check
        :param mac: at this time will add mac to debug output for future reference
        :param pass1: password info "TO BE PROVIDED IN OUTPUT" for future debug purposes.
        :param pass2: password info "TO BE PROVIDED IN OUTPUT" for future debug purposes.
        :param showpass: boolean to show or character over password to indicate 'if' a password was
                         provided.
        :param taillength: length of log messages (dmesg, syslog, etc) to retrieve
        :param net_namespace: the network namespace to gather info from (optional)
        :param loglevel: the python logging attribute to use. Loglevel of None or 0 is no logging.
        :returns string buf containing the dumped network info.
        """

        buf = ('Attempting to dump network information, args: ip:' + str(ip) +
               ' mac:' + str(mac) +
               ' pass1:' + self.get_masked_pass(pass1, show=showpass) +
               ' pass2:' + self.get_masked_pass(pass2, show=showpass))
        if ip:
            try:
                out = self.ping_cmd(ip, verbose=False, net_namespace=net_namespace, count=1)
                buf += out.get('output', None)
            except Exception as PE:
                buf += 'Ping cmd failed, err:"{0}"'.format(PE)
        if net_namespace:
            try:
                ns_list = self.sys('ip netns list')
                if ns_list:
                    buf += "\n"
                    buf += "\n".join(str(x) for x in ns_list)
                if net_namespace in ns_list:
                    self.sys('arp -a', net_namespace=net_namespace)
                    self.sys('ifconfig', net_namespace=net_namespace)
                    self.sys('netstat -rn', net_namespace=net_namespace)
            except Exception as NE:
                buf += 'Error fetching netns info, err:"{0}"'.format(NE)

        buf += self.sys('arp -a', listformat=False)
        buf += self.sys('dmesg | tail -' + str(taillength), listformat=False)
        buf += self.sys('cat /var/log/messages | tail -' + str(taillength), listformat=False)
        if loglevel:
            logger = getattr(self.log, loglevel, None)
            if logger:
                logger(buf)
        return buf

    def get_masked_pass(self, pwd, firstlast=True, charcount=True, show=False):
        '''
        format password for printing
        options:
        pwd - string- the text password to format
        firstlast -boolean - show the first and last characters in pwd
        charcount -boolean - print a "*" for each char in pwd, otherwise return fixed
                   string '**hidden**'
        show - boolean - convert pwd to str() and return it in plain text
        '''
        ret = ""
        if pwd is None:
            return ""
        if show is True:
            return str(pwd)
        if charcount is False:
            return "**hidden**"
        for x in xrange(0, len(pwd)):
            if (x == 0 or x == len(pwd)) and firstlast:
                ret = ret + pwd[x]
            else:
                ret += "*"

    #############################################################################################
    #                         Package Management                                                #
    #############################################################################################

    @property
    def package_manager(self):
        if not self._package_manager:
            self._package_manager = self._get_package_manager()
        return self._package_manager

    @package_manager.setter
    def package_manager(self, new_package_manager):
        self._package_manager = new_package_manager

    def _get_distro_info_from_machine(self, verbose=False):
        """
        Ubuntu 14.04.2
        CentOS release 6.6 (Final)
        """
        if not self.ssh:
            raise Exception('Need SSH connection to retrieve distribution info from machine')
        if self.is_file('/etc/os-release'):
            try:
                self.distro  = self.sys('. /etc/os-release && echo "$ID"', code=0)
                self.distro_ver = self.sys('. /etc/os-release && echo "$VERSION_ID"', code=0)
                return (self.distro, self.distro_ver)
            except CommandExitCodeException, CE:
                self.log.warning('Failed to fetch distro info from /etc/os-release, err:"{0}"'
                                 .format(CE))

        try:
            out = self.sys('cat /etc/issue', listformat=False, code=0, verbose=verbose)
        except CommandExitCodeException, CE:
            self.log.warning('Failed to fetch /etc/issue from machine:"{0}", err:"{1}"'
                           .format(self.hostname, str(CE)))
            out = None
        if out:
            try:
                self.distro = str(re.match("^\w+", out).group()).strip().lower()
                self.distro_ver = str(re.search("\s(\d+[\d, .]*)\s", out).group()).strip().lower()
            except Exception, DE:
                self.log.debug('Could not parse distro info from machine, err:' + str(DE))
        self.distro = self.distro or "UNKNOWN"
        self.distro_ver = self.distro_ver or "UNKNOWN"
        return (self.distro, self.distro_ver)

    def _get_package_manager(self, verbose=False):
        """
        Attempts to create a package manager obj based upon the detected package manager
        type.
        """
        try:
            self.sys('which yum', code=0)
            self.package_manager = Yum(self)
            return self.package_manager
        except CommandExitCodeException:
            try:
                self.sys('which apt', code=0, verbose=verbose)
                self.package_manager = Apt(self)
                return self.package_manager
            except CommandExitCodeException:
                pass
        raise RuntimeError('Unable to determine package manager for machine:{0}'
                           .format(self.hostname))

    def upgrade(self, package=None, nogpg=False):
        self.package_manager.upgrade(package, nogpg=nogpg)

    def add_repo(self, url, name="test-repo"):
        self.package_manager.add_repo(url, name)

    def install(self, package, nogpg=False, timeout=300):
        self.package_manager.install(package, nogpg=nogpg)

    def update_repos(self):
        self.package_manager.update_repos()

    def get_package_info(self, package_name):
        self.package_manager.get_package_info(package_name)

    def get_installed_packages(self):
        self.package_manager.get_installed_packages()

    #############################################################################################
    #                       Network Utilties                                                    #
    #############################################################################################

    @property
    def ssh(self):
        if not self._ssh:
            if self._do_ssh_connect:
                hostname = self.ssh_connect_kwargs.get('host', None)
                if not hostname:
                    raise ValueError('Host not provided in ssh_connect_kwargs for machine')
                # Check for a proxy
                hostname = self.ssh_connect_kwargs.get('proxy', None) or hostname
                port_status = False
                for x in xrange(0, 3):
                    try:
                        test_port_status(hostname, port=22, tcp=True, debug=self.log.debug)
                        port_status = True
                        break
                    except socketerror:
                        pass
                if port_status:
                    try:
                        self._ssh = SshConnection(**self.ssh_connect_kwargs)
                    except:
                        self.log.warning('Failed to establish ssh connection with args:"{0}"'
                                         .format(self.ssh_connect_kwargs))
                        raise
                else:
                    raise RuntimeError('Could not reach machine:"{0}"  at tcp/22'.format(hostname))
        return self._ssh

    @ssh.setter
    def ssh(self, newssh):
        self._ssh = newssh

    @property
    def sftp(self):
        if not getattr(self, '_sftp', None):
            sftp = self.ssh.connection.open_sftp()
            setattr(self, '_sftp', sftp)
        return self._sftp

    @sftp.setter
    def sftp(self, newsftp):
        setattr(self, '_sftp', newsftp)

    def refresh_ssh(self):
        self.ssh.refresh_connection()

    def start_interactive_ssh(self, timeout=180):
        """
        start a very basic interactive ssh session with this machine
        """
        return self.ssh.start_interactive(timeout=timeout)

    def refresh_connection(self):
        '''
        Attempt to restart/re-create a the machine's ssh connection
        '''
        self.ssh.refresh_connection()

    def interrupt_network(self, time=120, interface=None):
        '''
        Bounce a network interface on the remote machine.
        Used for test purposes
        '''
        defaults = ['eth1', 'em1']
        if not interface:
            for interface in defaults:
                try:
                    self.sys('ifconfig {0}'.format(interface), code=0)
                    break
                except CommandExitCodeException:
                    interface = None
                    pass
        if not interface:
            raise ValueError('interrupt_network. No interface provided, and defaults({0}) '
                             'not found on system'.format(", ".join(str(x) for x in defaults)))
        try:
            self.sys("ifdown " + interface + " && sleep " + str(time) + " && ifup " + interface,
                     timeout=3)
        except:
            pass

    def sys(self, cmd, verbose=True, timeout=120, listformat=True, code=None, net_namespace=None):
        '''
        Issues a command against the ssh connection to this instance
        Returns a list of the lines from stdout+stderr as a result of the command
        '''
        if net_namespace is not None:
            cmd = 'ip netns exec {0} {1}'.format(net_namespace, cmd)
        return self.ssh.sys(cmd, verbose=verbose, timeout=timeout, listformat=listformat,
                            code=code)

    def cmd(self, cmd, verbose=True, timeout=120, listformat=False, net_namespace=None,
            cb=None, cbargs=[]):
        '''
        Issues a command against the ssh connection to this instance
        returns dict containing:
            ['cmd'] - The command which was executed
            ['output'] - The std out/err from the executed command
            ['status'] - The exit (exitcode) of the command, in the case a call back fires,
                         this status code is unreliable.
            ['cbfired']  - Boolean to indicate whether or not the provided callback fired
                          (ie returned False)
            ['elapsed'] - Time elapsed waiting for command loop to end.
        cmd - mandatory - string, the command to be executed
        verbose - optional - boolean flag to enable debug
        timeout - optional - command timeout in seconds
        listformat -optional - specifies returned output in list of lines, or single string buffer
        net_namespace - optional - issue command in the network namespace provided.
        cb - optional - call back function, accepting string buffer, returning true false see s
                        shconnection for more info
        '''
        if net_namespace is not None:
            cmd = 'ip netns exec {0} {1}'.format(net_namespace, cmd)
        if (self.ssh is not None):
            return self.ssh.cmd(cmd, verbose=verbose, timeout=timeout, listformat=listformat,
                                cb=cb, cbargs=cbargs)
        else:
            raise Exception("Euinstance ssh connection is None")

    def sys_until_found(self, cmd, regex, verbose=True, timeout=120, listformat=True,
                        net_namespace=None):
        '''
        Run a command until output of command satisfies/finds regex or EOF is found.
        returns dict containing:
            ['cmd'] - The command which was executed
            ['output'] - The std out/err from the executed command
            ['status'] - The exit (exitcode) of the command, in the case a call back fires,
                         this status code is unreliable.
            ['cbfired']  - Boolean to indicate whether or not the provided callback fired
                          (ie returned False)
            ['elapsed'] - Time elapsed waiting for command loop to end.
        cmd - mandatory - string, the command to be executed
        regex - mandatory - regex to look for
        verbose - optional - boolean flag to enable debug
        timeout - optional - command timeout in seconds
        listformat -optional - specifies returned output in list of lines, or single string buffer
        '''
        return self.cmd(cmd, verbose=verbose, timeout=timeout, listformat=listformat,
                        net_namespace=net_namespace, cb=self.str_found_cb, cbargs=[regex, verbose])

    def _str_found_cb(self, buf, regex, verbose, search=True):
        """
        Return sshcbreturn type setting stop to True if given regex matches against
        given string buf
        """
        if verbose:
            self.log.debug(str(buf))
        return SshCbReturn(stop=self._str_found(buf, regex=regex, search=search))

    def _str_found(self, buf, regex, search=True):
        """
        Return True if given regex matches against given string
        """
        if search:
            found = re.search(regex, buf)
        else:
            found = re.match(regex, buf)
        if found:
            return True
        else:
            return False

    def wget_remote_image(self,
                          url,
                          path=None,
                          dest_file_name=None,
                          user=None,
                          password=None,
                          retryconn=True,
                          timeout=300):
        """
        Wrapper, monitor and display for a remote wget session issued on this machine obj.

        :param url: url to wget
        :param path: wget's -P param
        :param dest_file_name: wget's -O param for destination
        :param user: user for wget auth if needed
        :param password: password for wget auth if needed
        :param retryconn: wget's bool used include --retry-connrefused param
        :param timeout: the overall timeout for the wget command being executed on this machine
        :raise RuntimeError upon wget failure/error.
        """
        self.log.debug('wget_remote_image, url:' + str(url) + ", path:" + str(path))
        cmd = 'wget '
        if path:
            cmd = cmd + " -P " + str(path)
        if dest_file_name:
            cmd = cmd + " -O " + str(dest_file_name)
        if user:
            cmd = cmd + " --user " + str(user)
        if password:
            cmd = cmd + " --password " + str(password)
        if retryconn:
            cmd += ' --retry-connrefused '
        cmd = cmd + ' ' + str(url)
        self.log.debug('wget_remote_image cmd: ' + str(cmd))
        ret = self.cmd(cmd, timeout=timeout, cb=self.wget_status_cb)
        if ret['status'] != 0:
            raise RuntimeError('wget_remote_image failed with status:' + str(ret['status']))
        if not dest_file_name:
            dest_file_name = os.path.basename(url)
        dest_path = os.path.join((path or ""), dest_file_name)
        self.log.debug('wget_remote_image succeeded: "{0}"'.format(dest_path))
        return dest_path    


    def wget_status_cb(self, buf):
        """
        Callback to be used to provide real time status during a remote wget session
        """
        ret = SshCbReturn(stop=False)
        try:
            buf = buf.strip()
            val = buf.split()[0]
            if val != self.wget_last_status:
                if re.match('^\d+\%', buf):
                    sys.stdout.write("\r\x1b[K" + str(buf))
                    sys.stdout.flush()
                    self.wget_last_status = val
                else:
                    print buf
        except Exception, e:
            pass
        finally:
            return ret

    def ping_check(self, host, verbose=True, net_namespace=None):
        """
        Wrapper for ICMP ping requests/checks.
        :param host: remote host to ping from this machine obj
        :param verbose: log additional output from this ping command(s)
        :param net_namespace: the Linux network namespace on this machine obj to run ping from.
        :raises RuntimeError if ping fails.
        """
        out = self.ping_cmd(host, verbose=verbose, net_namespace=net_namespace)
        self.debug('Ping attempt to host:'+str(host)+", status code:"+str(out['status']))
        if out['status'] != 0:

            raise RuntimeError('{0}\nPing to host:"{1}" returned status:{2}'
                               .format(out.get('output', None), host, out.get('status', None)))
        return out

    def ping_cmd(self, host, count=2, pingtimeout=10, commandtimeout=120, listformat=False,
                 verbose=True, net_namespace=None):

        """
        Wrapper for the ping command to be executed on this machine obj

        :param host: remote host to ping from this machine obj
        :param count: number of ping attempts to be provided to ping command.
        :param pingtimeout: timeout param to be provided to 'ping' command for it's timeout
        :param commandtimeout: Time to wait for the ssh command issuing ping to complete
        :param listformat: bool, if true provides a list of lines, else a single string buffer
        :param verbose: log additional output from this ping command(s)
        :param net_namespace: the Linux network namespace on this machine obj to run ping from.
        :return: the response from the ping command(s)
        """
        cmd = 'ping -c ' + str(count) + ' -t ' + str(pingtimeout)
        if verbose:
            cmd += ' -v '
        cmd = cmd + ' ' + str(host)
        self.debug('cmd: {0}'.format(cmd))
        out = self.cmd(cmd, verbose=verbose, timeout=commandtimeout, listformat=listformat,
                       net_namespace=net_namespace)
        self.debug('out: {0}'.format(out))
        if verbose:
            # print all returned attributes from ping command dict
            for item in sorted(out):
                self.debug(str(item) + " = " + str(out[item]))
        return out

    def get_hostnames(self, cache_interval=60):
        """
        Attempts to fetch ip/hostname info (primarily used to identify this machine)
        :return: set of strings
        """
        hostnames = set([])
        if self.hostname:
            hostnames.add(self.hostname)
        try:
            out = self.sys('hostname', code=0)
            if out:
                hostnames.add(out[0])
        except Exception as E:
            self.log.warning('Error fetching hostname from machine:"{0}"'.format(E))
        try:
            ipv4_dict = self.get_network_ipv4_info(cache_interval=cache_interval).iteritems()
            for iface, info in ipv4_dict:
                ip = info.get('ip', None)
                if ip:
                    hostnames.add(ip)
        except Exception as HE:
            self.log.warning('Error parsing ip info for hostnames:"{0}"'.format(HE))
        return hostnames


    def get_network_ipv4_info(self, search_name=None, cache_interval=60, verbose=False):
        if cache_interval:
            interfaces = getattr(self, '_network_ipv4_info', {}) or {}
            if interfaces and (time.time() - interfaces.get('timestamp', 0) <= cache_interval):
                return interfaces.get('ipv4_info')
        interfaces = {}
        out = self.sys('ip -o -f inet  addr', code=0, verbose=verbose)
        assert isinstance(out, list)
        for line in out:
            if search_name and not re.search(search_name, line):
                continue
            info = line.split()
            num = info[0]
            iface = info[1]
            info = info[2:]
            info_len = len(info)
            offset = 0
            info_dict = {}
            info_dict['ip'] = None
            info_dict['mask'] = None
            info_dict['ipcidr'] = None
            info_dict['broadcast'] = None
            info_dict['scope'] = None
            info_dict['network'] = None
            info_dict['network_cidr'] = None
            while offset < info_len:
                word = info[offset]
                if word == 'inet':
                    offset += 1
                    info_dict['ipcidr'] = info[offset]
                    info_dict['ip'], mask = info_dict['ipcidr'].split('/')
                    if info_dict['ipcidr']:
                        net_info = get_network_info_for_cidr(info_dict['ipcidr']) or {}
                        info_dict['network'] = net_info.get('network', None)
                        info_dict['mask'] = net_info.get('netmask')
                        info_dict['network_cidr'] = "{0}/{1}".format(info_dict['network'], mask)
                if word == 'brd':
                    offset += 1
                    info_dict['broadcast'] = info[offset]
                if word == 'scope':
                    offset += 1
                    info_dict['scope'] = info[offset]
                offset += 1
            interfaces[iface] = info_dict
        cache_dict = {'timestamp': time.time(), 'ipv4_info': interfaces}
        setattr(self, '_network_ipv4_info', cache_dict)
        return interfaces

    def show_network_ipv4_info(self, search_name=None, info_dict=None, printmethod=None,
                               printme=True):
        if search_name and info_dict:
            self.log.warning('show_network_ipv4_info method only supports '
                             'search_name or info_dict, not both')
        info_dict = info_dict or self.get_network_ipv4_info(search_name=search_name)

        header = ['INTERFACE', 'CIDR', 'IP', 'MASK', 'BROADCAST', 'SCOPE']
        pt = PrettyTable(header)
        pt.align = 'l'
        for iface, info in info_dict.iteritems():
            pt.add_row([iface, info['network_cidr'], info['ip'], info['mask'], info['broadcast'],
                        info['scope']])
        if not printme:
            return pt
        printmethod = printmethod or self.log.info
        printmethod("\n{0}\n".format(pt))


    def get_network_interfaces(self, search_name=None, proc='/proc/net/dev', verbose=False):
        interfaces = {}
        time_stamp = int(time.time())
        out = None
        for retry in xrange(0, 3):
            out = self.sys('cat {0}'.format(proc), code=0, verbose=verbose)
            if out:
                break
            else:
                time.sleep(1)
        if not out:
            raise ValueError('Failed to fetch net interface info from "{0}", output:"{1}"'
                             .format(proc, out))
        assert isinstance(out, list)
        header_line = out[0]
        headers = []
        for h in str(header_line).upper().split('|'):
            headers.append(h.strip())
        headers[0] = 'INTERFACE'
        sections = []
        section_line = out[1]
        header_index = 0
        header = headers[header_index]
        section_line = str(section_line).replace('|', ' | ').upper()
        for section in str(section_line).split():
            section = section.strip()
            if section == '|':
                header_index += 1
                header = headers[header_index]
            else:
                sections.append("{0}_{1}".format(headers[header_index], section))
        for line in out[2:]:
            columns = line.split()
            iface_name = str(columns[0]).strip(':')
            if search_name and not re.search(search_name, iface_name):
                continue
            else:
                interface = {}
                for x in xrange(1, len(columns)):
                    interface[sections[x]] = columns[x].strip()
                interfaces[iface_name] = interface
        return interfaces

    def show_network_interfaces_table(self, search_name=None, interfaces=None, empty_header_min=4,
                                     header_min=6, printmethod=None, printme=True):
        interfaces = interfaces or self.get_network_interfaces(search_name=search_name)
        headers = ['IFACE']
        for value in interfaces.values()[0].keys():
            header = (re.sub('TRANSMIT_', 'TX', re.sub('RECEIVE_', 'RX', value)).strip())
            headers.append(header)
        pt = PrettyTable(headers)
        pt.hrules = 1
        pt.header = False
        pt.align = 'l'
        pt.padding_width = 0
        for key, value in interfaces.iteritems():
            pt.add_row([markup(key, [1, 94])] + value.values())
        opt = pt._get_options({})
        pt._compute_widths(pt._format_rows(pt._rows, opt), opt)
        fake_header = []
        for x in xrange(0, len(pt.field_names)):
            if pt._widths[x] > 1:
                if pt._widths[x] > header_min:
                    limit = pt._widths[x]
                else:
                    limit = header_min
            else:
                limit = empty_header_min
            fake_header.append(markup(pt.field_names[x][0:limit], [4]))
        pt._rows = [fake_header] + pt._rows
        if not printme:
            return pt
        printmethod = printmethod or self.log.info
        printmethod("\n{0}\n".format(pt))

    def get_network_interfaces_delta(self, search_name=None):
        last = getattr(self, '_net_iface_stats', {})
        if last is None:
            last = {}
        elapsed = None
        old_interfaces = {}
        new_interfaces = {}
        delta = {}
        if last:
            lasttime = last.get('timestamp')
            interfaces = last.get('interfaces')
            if search_name:
                for key, value in interfaces.iteritems():
                    if re.search(search_name, key):
                        old_interfaces[key] = value
            else:
                old_interfaces = interfaces
            elapsed = float("{0:.2f}".format(time.time() - lasttime))
        # Fetch new dict w/o filters to cache all entries, filter afterward
        new_fetch = self.get_network_interfaces()
        self._net_iface_stats = {'timestamp': time.time(), 'interfaces': new_fetch}
        if search_name:
            for key, value in new_fetch.iteritems():
                if re.search(search_name, key):
                    new_interfaces[key] = value
            if not new_interfaces:
                self.log.info('No interfaces found matching string: "{0}"'.format(search_name))
        else:
            new_interfaces = new_fetch
        for iface_name, new_iface_dict in new_interfaces.iteritems():
            iface_delta_dict = {}
            if iface_name in old_interfaces:
                old_dict = old_interfaces.get(iface_name)
                for key, value in new_iface_dict.iteritems():
                    iface_delta_dict[key] = int(value) - int(old_dict.get(key, 0))
            else:
                iface_delta_dict = new_iface_dict
            delta[iface_name] = iface_delta_dict
        return {'elapsed': elapsed, 'interfaces': delta}

    def show_network_interfaces_delta(self, search_name=None, printmethod=None, printme=True):
        delta = self.get_network_interfaces_delta(search_name=search_name)
        pt = self.show_network_interfaces_table(interfaces=delta.get('interfaces', {}),
                                               printme=False)
        buf = markup("Time Elapsed Since Last Update: {0}\n".format(delta.get('elapsed')),
                     [1, 4, 91])
        buf += pt.get_string() + "\n"
        if not printme:
            return pt
        printmethod = printmethod or self.log.info
        printmethod(buf)

    ###############################################################################################
    #                           OS/System Utilties                                                #
    ###############################################################################################

    @property
    def _mem_info(self):
        # Returns a dict of free mem stats from this machine obj.
        # results are cached for '_sys_stats_interval' seconds.
        # to force an update set '_free_stats' to None before fetching.
        if not self._free_stats.get('stats', None) or \
                (time.time() - self._free_stats.get('last_updated', 0) > self._sys_stats_interval):
            header = []

            def newstats(total, used, free):
                return {'total': total, 'used': used, 'free': free}

            free_stats = {}
            try:
                out = self.sys('free -m', code=0, verbose=False)
                for line in out:
                    line = str(line).lower().split()
                    if not header:
                        if 'total' in line:
                            header = ['title'] + line
                    else:
                        for memtype in ['mem', 'swap']:
                            if "{0}:".format(memtype) in line:
                                free_stats[memtype] = newstats(
                                    total=line[header.index('total')],
                                    used=line[header.index('used')],
                                    free=line[header.index('free')])
                                break
                free_stats['last_updated'] = time.time()
            except Exception as CE:
                self.log.warn('{0}\n{1}\nFailed to update mem stats:"{2}"'
                              .format("\n".join(out or []), get_traceback(), CE))
            self._free_stats['stats'] = free_stats

        return self._free_stats.get('stats', {})

    @property
    def arch(self):
        # Marchine arch (ie x86_64)
        if not self._arch:
            self._get_arch_info_from_machine()
        return self._arch

    @arch.setter
    def arch(self, value):
        # Marchine arch (ie x86_64)
        self._arch = value

    @property
    def distro(self):
        # Linux Distribution information
        if not self._distroname:
            distro, ver = self._get_distro_info_from_machine()
            self._distroname = distro
            self._distrover = ver
        return self._distroname

    @distro.setter
    def distro(self, new_distro):
        # Linux Distribution information
        self._distroname = new_distro

    @property
    def distro_ver(self):
        # Linux Distribution information
        if not self._distrover:
            distro, ver = self._get_distro_info_from_machine()
            self._distroname = distro
            self._distrover = ver
        return self._distrover

    @distro_ver.setter
    def distro_ver(self, new_distro):
        # Linux Distribution information
        self._distrover = new_distro

    def _get_arch_info_from_machine(self, verbose=False):
        '''
        Attempt to detect and assign the arch info for this machine
        '''
        try:
            arch = self.sys('uname -p', code=0, verbose=verbose)[0]
            self._arch = arch
            return arch
        except Exception, UE:
            self.log.debug('Failed to get arch info from:"{0}", err:"{1}"'
                           .format(self.hostname, str(UE)))
        return None

    def get_free_mem(self):
        val = self._mem_info.get('mem', {}).get('free', None)
        if val is not None:
            val = int(val)
        return val

    def get_total_mem(self):
        val = self._mem_info.get('mem', {}).get('total', None)
        if val is not None:
            val = int(val)
        return val

    def get_used_mem(self):
        val = self._mem_info.get('mem', {}).get('used', None)
        if val is not None:
            val = int(val)
        return val

    def get_swap_used(self):
        val = self._mem_info.get('swap', {}).get('used', None)
        if val is not None:
            val = int(val)
        return val

    def get_uptime(self):
        # fetch uptime of remote machine from proc uptime
        return int(self.sys('cat /proc/uptime', code=0)[0].split()[1].split('.')[0])

    def mkfs(self, partition, type="ext3"):
        self.sys("mkfs." + type + " -F " + partition)

    def mount(self, device, path):
        self.sys("mount " + device + " " + path)

    def show_sys_info(self, mem=True, cpu=True, disk=True, print_method=None, print_table=True):
        print_method = print_method or self.log.info
        sys_pt = PrettyTable(['name', 'value', 'percent'])
        sys_pt.header = False
        sys_pt.border = 0
        sys_pt.align = 'l'
        sys_pt.padding_width = 0
        if mem:
            sys_pt.add_row([markup("Mem:", [1, 4]), "", ""])
            free = self.get_free_mem() or 0
            used = self.get_used_mem() or 0
            total = self.get_total_mem() or 0
            swap = self.get_swap_used() or 0
            per_used = "{0:.1f}".format((used / float(total)) * 100)
            per_free = "{0:.1f}".format((free / float(total)) * 100)
            per_swap = "{0:.1f}".format((swap / float(total)) * 100)
            sys_pt.add_row([" Used:", "{0}".format(used), " {0}%".format(per_used)])
            sys_pt.add_row([" Free:", "{0}".format(free), " {0}%".format(per_free)])
            sys_pt.add_row([" Swap:", "{0}".format(swap), " {0}%".format(per_swap)])
        if cpu:
            sys_pt.add_row([markup("CPU:", [1, 4]), "", ""])
            cpu_info = self.cpu_info
            all = cpu_info.pop('all', None)
            for cpu in sorted(cpu_info):
                values = cpu_info[cpu]
                sys_pt.add_row([" #{0}:".format(cpu), "{0}%".format(values.get('used', None)), ""])
        if disk:
            sys_pt.add_row([markup("DISK:", [1, 4]), "", ""])
            disk_info = self.get_disk_summary()
            for fs, info in disk_info.iteritems():
                sys_pt.add_row([os.path.basename(fs) + " ", info.get('size'), info.get('use%')])
        if print_table:
            print_method("\n{0}\n".format(sys_pt))
        return sys_pt

    ###############################################################################################
    #                               Process Utils                                                 #
    ###############################################################################################

    @property
    def cpu_info(self):
        # Returns a dict of cpu stats from this machine obj.
        # results are cached for '_sys_stats_interval' seconds.
        # to force an update set '_cpu_stats' to None before fetching.
        if not self._cpu_stats.get('stats', None) or \
                (time.time() - self._cpu_stats.get('last_updated', 0) > self._sys_stats_interval):
            header = []

            def newstats(usr, nice, sys, iowait, idle):
                return {'usr': usr,
                        'nice': nice,
                        'sys': sys,
                        'iowait': iowait,
                        'idle': idle,
                        'used': 100 - float(idle)}

            cpu_stats = {}
            out = []
            try:
                out = self.sys('mpstat -P ALL', code=0, verbose=False)
                for line in out:
                    line = str(line).lower().split()
                    if not header:
                        if '%idle' in line:
                            header = line
                    elif line:
                        cpu = line[header.index('cpu')]
                        if cpu != 'all':
                            cpu = int(cpu)
                        cpu_stats[cpu] = newstats(
                            usr=line[header.index('%usr')],
                            nice=line[header.index('%nice')],
                            sys=line[header.index('%sys')],
                            iowait=line[header.index('%iowait')],
                            idle=line[header.index('%idle')])

                self._cpu_stats['last_updated'] = time.time()
            except Exception as CE:
                self.log.warn('{0}\n{1}\nFailed to update cpu stats:"{2}"'
                              .format("\n".join(out or []), get_traceback(), CE))
            self._cpu_stats['stats'] = cpu_stats
        return self._cpu_stats.get('stats', {})

    def get_service_is_running_status(self, service, code=0):
        """
        Checks status of service 'service' on the machine obj.
        :param service: string representing service name
        :return: boolean.
        """
        try:
            self.sys("service " + str(service) + " status", code=0)
            return True
        except CommandExitCodeException:
            return False
        except Exception, e:
            self.log.debug('Could not get "{0}" service state from machine: {1}, err:{2}'
                           .format(service, self.hostname, str(e)))

    def get_elapsed_seconds_since_pid_started(self, pid):
        """
        Attempts to parse ps time elapsed since process/pid has been running and return the
        presented time in elapsed number of seconds.
        :param pid: Process id to get elapsed time from
        :return: Elapsed time in seconds that pid has been running
        """
        seconds_min = 60
        seconds_hour = 3600
        seconds_day = 86400
        elapsed = 0
        try:
            if not pid:
                raise Exception('Empty pid passed to get_elapsed_seconds_since_pid_started')
            cmd = "ps -eo pid,etime | grep " + str(pid) + " | awk '{print $2}'"
            self.log.debug('starting get pid uptime"' + str(cmd) + '"...')
            # expected format: days-HH:MM:SS
            out = self.sys(cmd, code=0)[0]
            out = out.strip()
            if re.search("-", out):
                split_out = out.split("-")
                days = int(split_out[0])
                time_string = split_out[1]
            else:
                days = 0
                time_string = out

            split_time = time_string.split(':')
            # insert a 0 if hours, and minutes are not present.
            for x in xrange(len(split_time), 3):
                split_time.insert(0, 0)

            hours = int(split_time[0] or 0)
            minutes = int(split_time[1] or 0)
            seconds = int(split_time[2] or 0)
            elapsed = seconds + (minutes * seconds_min) + (hours * seconds_hour) + (
                days * seconds_day)
        except Exception, ES:
            self.log.debug('{0}\n"get_elapsed_seconds_since_pid_started" error: "{1}"'
                           .format(get_traceback(), str(ES)))
        return int(elapsed)

    def get_pid_info(self, pid, ps_cols=None):
        ret = {}
        ps_cols = ps_cols or ['etime', 'pcpu', 'pmem']
        if 'comm' not in ps_cols:
            ps_cols.append('comm')
        try:
            out = self.sys('ps -p {0} --ppid {0} -o {1}'.format(pid, ",".join(ps_cols)), code=0)
        except CommandExitCodeException as CE:
            self.log.debug('Error fetching info for pid:{0}, err:"{1}"'.format(pid, str(CE)))
        else:
            if len(out) >= 2:
                header = out[0].split()
                command_index = header.index('COMMAND')
                header.remove('COMMAND')
                for line in out[1:]:
                    values = line.split()
                    command = values.pop(command_index)
                    new_dict = {}
                    for h_name in header:
                        new_dict[h_name] = values[header.index(h_name)]
                    ret[command] = new_dict
        return ret

    def found(self, command, regex, verbose=True):
        """ Returns a Boolean of whether the result of the command contains the regex"""
        result = self.sys(command, verbose=verbose)
        if result is None or result == []:
            return False
        for line in result:
            found = re.search(regex, line)
            if found:
                return True
        return False

    #############################################################################################
    #                       User Related Utils                                                  #
    #############################################################################################

    def get_users(self):
        '''
        Attempts to return a list of normal linux access local to this instance.
        Returns a list of all non-root access found within the uid_min/max range who are
        not marked nologin
        '''
        users = []
        try:
            uid_min = str(self.sys("grep ^UID_MIN /etc/login.defs | awk '{print $2}'")[0]).strip()
            uid_max = str(self.sys("grep ^UID_MAX /etc/login.defs | awk '{print $2}'")[0]).strip()
            try:
                users = str(self.sys("cat /etc/passwd | grep -v nologin | awk -F: '{ if ( $3 >= " +
                                     str(uid_min) + " && $3 <= " + str(uid_max) +
                                     " ) print $0}' ")[0]).split(":")[0]
            except IndexError, ie:
                self.log.debug("No access found, passing exception:" + str(ie))
                pass
            return users
        except Exception, e:
            self.log.debug("Failed to get local access. Err:" + str(e))

    def get_user_password(self, username):
        '''
        Attempts to verify whether or not a user 'username' has a password set or not on
        this instance.
        returns true if a password is detected, else false

        '''
        password = None
        out = self.sys("cat /etc/passwd | grep '^" + str(username) + "'")
        if out != []:
            self.log.debug("pwd out:" + str(out[0]))
            if (str(out[0]).split(":")[1] == "x"):
                out = self.sys("cat /etc/shadow | grep '^" + str(username) + "'")
                if out != []:
                    password = str(out[0]).split(":")[1]
                    if password == "" or re.match("^!+$", password):
                        password = None
        return password

    def get_user_group_info(self, username, index=3):
        '''
        Attempts to return a list of groups for a specific user on this instance.
        index is set at the grouplist by default [3], but can be adjust to include the username,
        password, and group id as well in the list.
        where the parsed string should be in format 'name:password:groupid1:groupid2:groupid3...'
        '''
        groups = []
        out = []
        try:
            out = self.sys("cat /etc/group | grep '^" + str(username) + "'")
            if out != []:
                groups = str(out[0]).strip().split(":")
                # return list starting at group index
                groups = groups[index:len(groups)]
            return groups
        except Exception, e:
            self.log.debug("No group found for user:" + str(username) + ", err:" + str(e))

    ###############################################################################################
    #                       File Related Utils                                                    #
    ###############################################################################################

    def chown(self, user, path):
        self.sys("chwon " + user + ":" + user + " " + path)

    def get_abs_path(self, path):
        out = self.sys('echo "$(cd "$(dirname "{0}")" && pwd)/$(basename "{0}")"'.format(path),
                       code=0)
        if out:
            path = os.path.normpath(str(out[0]).strip())
            path.rstrip('.')
            path.rstrip('/') + "/"
            return path
        return None

    def _file_test(self, testchar, path):
        testchar = str(testchar).rstrip('-')
        try:
            self.sys('[ -{0} {1} ]'.format(testchar, path), code=0)
            return True
        except CommandExitCodeException:
            return False

    def is_file(self, path):
        return self._file_test('f', path)

    def is_dir(self, path):
        return self._file_test('d', path)

    def is_block_dev(self, path):
        return self._file_test('b', path)

    def is_readable(self, path):
        return self._file_test('r', path)

    def is_writeable(self, path):
        return self._file_test('w', path)

    def is_executable(self, path):
        return self._file_test('x', path)

    def is_present(self, filepath):
        return self._file_test('e', filepath)

    def get_file_stat(self, path):
        return self.sftp.lstat(path)

    def get_file_size(self, path):
        return self.sftp.lstat(path).st_size

    def get_file_perms_flag(self, path):
        return self.sftp.lstat(path).FLAG_PERMISSIONS

    def get_file_groupid(self, path):
        return self.sftp.lstat(path).st_gid

    def get_file_userid(self, path):
        return self.sftp.lstat(path).st_uid

    def open_remote_file(self, filepath, mode):
        f = self.ssh.sftp.file(filepath, mode)
        return f

    @printinfo
    def dd_monitor(self,
                   ddif=None,
                   ddof=None,
                   ddcount=None,
                   ddbs=1024,
                   ddbytes=None,
                   ddcmd=None,
                   ddseek=None,
                   timeout=300,
                   poll_interval=1,
                   tmpfile=None,
                   sync=True):
        '''
        Executes dd command on instance, monitors and displays ongoing status, and returns
        stats dict for dd outcome
        :type ddif: str
        :param ddif: Interface to read data in from

        :type ddof: str
        :param ddof: Interface to write data to

        :type ddcount: int
        :param ddcount: Number or count of block size (ddbs) to read/write

        :type ddbs: int
        :param ddbs: Block size used for  reads/writes

        :type ddbytes: int
        :param ddbytes: Number of bytes to be roughly r/w (note: used as ddbytes/ddbs = count)

        :type ddcmd: str
        :param ddcmd: String representing a preformed dd comand to be executed and monitored

        :type ddseek: int
        :param ddseek: length of ddof file to seek before writing

        :type timeout: int
        :param timeout: Number of seconds to wait before timing out on dd cmd.

        :type poll_interval: int
        :param poll_interval: Number of seconds to pause between polling dd and updating status

        :type tmpfile: str
        :param tmpfile: temp file used on remote instance to redirect dd's stderr to in order
                        to nohup dd.

        :rtype: dict
        :returns: dict containing dd stats
        '''
        mb = 1048576  # bytes per mb
        gig = 1073741824  # bytes per gig
        # this tmp file will be created on remote instance to write stderr from dd to...
        if not tmpfile:
            tstamp = time.time()
            tmpfile = '/tmp/eutesterddcmd.{0}.{1}'.format(self.hostname, str(int(tstamp))[-4:])
        tmppidfile = tmpfile + ".pid"
        # init return dict
        ret = {
            'dd_records_in': 0,
            'dd_records_out': 0,
            'dd_bytes': 0,
            'dd_mb': 0,
            'dd_gig': 0,
            'dd_elapsed': 0,
            'dd_rate': 0,
            'dd_units': "",
            'dd_full_rec_in': 0,
            'dd_full_rec_out': 0,
            'dd_partial_rec_in': 0,
            'dd_partial_rec_out': 0,
            'test_time': 0,
            'test_rate': 0,
            'ddcmd': ""}
        dd_units = 0
        elapsed = 0
        done = False
        infobuf = None
        outbuf = None
        start = time.time()
        if ddcmd:
            ddcmd = ddcmd
        else:
            if not ddif or not ddof:
                raise Exception('dd_monitor needs ddif and ddof, or a preformed ddcmd string')
            ddbs_str = str(' bs=' + str(ddbs) + ' ') or ""
            if ddcount:
                ddcount_str = str(' count=' + str(ddcount) + ' ')
            elif ddbytes and ddbs:
                ddcount_str = str(' count=' + str((ddbytes / ddbs) or 1) + ' ')
            else:
                ddcount_str = ''
            if ddseek:
                ddseek_str = str(' seek=' + str(ddseek) + ' ')
            else:
                ddseek_str = ''
            ddcmd = str('dd if=' + str(ddif) + ' of=' + str(ddof) + str(ddseek_str) +
                        str(ddbs_str) + str(ddcount_str))
            ret['ddcmd'] = ddcmd

        # Due to the ssh psuedo tty, this is done in an ugly manner to get output of
        # future usr1 signals for dd status updates and allow this to run with nohup in the
        # background. Added sleep so cmd is nohup'd before tty is terminated (maybe?)
        try:
            cmd = 'nohup ' + str(ddcmd) + ' 2> ' + str(tmpfile) + ' & echo $! && sleep 2'
            # Execute dd command and store echo'd pid from output
            try:
                dd_pid = self.sys(cmd, code=0)[0]
            except CommandExitCodeException, se:
                dbg_buf = ""
                file_contents = self.sys('cat ' + str(tmpfile))
                if file_contents:
                    dbg_buf = "\n".join(file_contents)
                raise Exception('Failed dd cmd:"' + str(cmd) + '", tmpfile contents:\n' +
                                str(dbg_buf))

            # Form the table headers for printing dd status...
            linediv = '\n---------------------------------------------------------------' \
                      '-------------------------------------------------------------\n'
            databuf = str('BYTES').ljust(15)
            databuf += '|' + str('MBs').center(15)
            databuf += '|' + str('GIGs').center(8)

            timebuf = '|' + str('DD TIME').center(10)
            timebuf += '|' + str('TEST TIME').center(10)

            ratebuf = '|' + str('DD RATE').center(12)
            ratebuf += '|' + str('TEST RATE').center(12)

            recbuf = '|' + str('REC_IN').center(18)
            recbuf += '|' + str('REC_OUT').center(18)

            info_header = str('DD DATA INFO').ljust(len(databuf))
            info_header += '|' + str('DD TIME INFO').center(len(timebuf) - 1)
            info_header += '|' + str('DD RATE INFO').center(len(ratebuf) - 1)
            info_header += '|' + str('DD RECORDS FULL/PARTIAL INFO').center(len(recbuf) - 1)

            buf = linediv
            buf += info_header
            buf += linediv
            buf += databuf + timebuf + ratebuf + recbuf
            buf += linediv
            sys.stdout.write(buf)
            sys.stdout.flush()
            dd_exit_code = -1
            # Keep getting and printing dd status until done...
            while not done and (elapsed < timeout):
                # send sig usr1 to have dd process dump status to stderr redirected to tmpfile
                output = self.cmd('kill -USR1 ' + str(dd_pid), verbose=False)
                cmdstatus = int(output['status'])
                if cmdstatus != 0:
                    done = True
                    cmdout = self.cmd('wait {0}'.format(dd_pid), verbose=False)
                    dd_exit_code = int(cmdout['status'])
                    # if the command returned error, process is done
                    out = self.sys('cat ' + str(tmpfile) + "; rm -f " + str(tmpfile), code=0,
                                   verbose=False)
                else:
                    # if the above command didn't error out then dd ps is still running,
                    # grab status from tmpfile, and clear it
                    out = self.sys('cat ' + str(tmpfile) + " && echo '' > " + str(tmpfile) +
                                   ' 2>&1 > /dev/null', code=0, verbose=False)
                for line in out:
                    line = str(line)
                    try:
                        if re.search('records in', line):
                            ret['dd_records_in'] = str(line.split()[0]).strip()
                            ret['dd_full_rec_in'] = \
                                str(ret['dd_records_in'].split("+")[0].strip())
                            # dd_full_rec_in = int(dd_full_rec_in)
                            ret['dd_partial_rec_in'] = \
                                str(ret['dd_records_in'].split("+")[1].strip())
                            # dd_partial_rec_in = int(dd_partial_rec_in)
                        elif re.search('records out', line):
                            ret['dd_records_out'] = str(line.split()[0]).strip()
                            ret['dd_full_rec_out'] = \
                                str(ret['dd_records_out'].split("+")[0].strip())
                            # dd_ful_rec_out = int(dd_full_rec_out)
                            ret['dd_partial_rec_out'] = str(ret['dd_records_out'].split("+")[1]
                                                            .strip())
                            # dd_partial_rec_out = int(dd_partial_rec_out)
                        elif re.search('copied', line):
                            # 123456789 bytes (123 MB) copied, 12.34 s, 123.45 MB/s
                            summary = line.split()
                            ret['dd_bytes'] = int(summary[0])
                            ret['dd_mb'] = float("{0:.2f}".format(ret['dd_bytes'] / float(mb)))
                            ret['dd_gig'] = float("{0:.2f}".format(ret['dd_bytes'] / float(gig)))
                            ret['dd_elapsed'] = float(summary[5])
                            ret['dd_rate'] = float(summary[7])
                            ret['dd_units'] = str(summary[8])
                    except Exception, e:
                        # catch any exception in the data parsing and show it as info/debug later
                        tb = get_traceback()
                        infobuf = '\n\nCaught exception while processing line:"' + str(line) + '"'
                        infobuf += '\n' + str(tb) + "\n" + str(e) + '\n'
                elapsed = float(time.time() - start)
                ret['test_rate'] = float("{0:.2f}".format(ret['dd_mb'] / elapsed))
                ret['test_time'] = "{0:.4f}".format(elapsed)
                # Create and format the status output buffer, then print it...
                buf = str(ret['dd_bytes']).ljust(15)
                buf += '|' + str(ret['dd_mb']).center(15)
                buf += '|' + str(ret['dd_gig']).center(8)
                buf += '|' + str(ret['dd_elapsed']).center(10)
                buf += '|' + str(ret['test_time']).center(10)
                buf += '|' + str(str(ret['dd_rate']) + " " + str(ret['dd_units'])).center(12)
                buf += '|' + str(str(ret['test_rate']) + " " + str('MB/s')).center(12)
                buf += '|' + str("F:" + str(ret['dd_full_rec_in']) + " P:" +
                                 str(ret['dd_partial_rec_in'])).center(18)
                buf += '|' + str("F:" + str(ret['dd_full_rec_out']) + " P:" +
                                 str(ret['dd_partial_rec_out'])).center(18)
                sys.stdout.write("\r\x1b[K" + str(buf))
                sys.stdout.flush()
                time.sleep(poll_interval)
            sys.stdout.write(linediv)
            sys.stdout.flush()
            elapsed = int(time.time() - start)
            if not done:
                # Attempt to kill dd process...
                self.sys('kill ' + str(dd_pid))
                raise RuntimeError('dd_monitor timed out before dd cmd completed, elapsed:{0}/{1}'
                                   .format(str(elapsed), str(timeout)))
            else:
                # sync to ensure writes to dev
                if sync:
                    self.sys('sync', code=0)
                    elapsed = int(time.time() - start)
            # if we have any info from exceptions caught during parsing, print that here...
            if infobuf:
                print infobuf
            # format last output for debug in case of errors
            if out:
                outbuf = "\n".join(out)
            # Check for exit code of dd command, 127 may indicate dd process ended before wait pid,
            # use additional checks below to determine a failure when 127 is returned.
            if dd_exit_code != 127 and dd_exit_code != 0:
                raise CommandExitCodeException('dd cmd failed with exit code:' + str(dd_exit_code))
            # if we didn't transfer any bytes of data, assume the cmd failed and wrote to stderr
            # now in outbuf...
            if not ret['dd_full_rec_out'] and not ret['dd_partial_rec_out']:
                raise CommandExitCodeException('Did not transfer any data using dd cmd:' +
                                               str(ddcmd) + "\nstderr: " + str(outbuf))
            # Check in vs out, allow for a difference of 1 record...
            if (abs(int(ret['dd_full_rec_in']) - int(ret['dd_full_rec_out'])) > 1 or
                    abs(int(ret['dd_partial_rec_out']) - int(ret['dd_partial_rec_in'])) > 1):
                raise CommandExitCodeException('dd in records do not match out records in '
                                               'transfer. full_in:{0}, part_in:{1} != '
                                               'full_out:{2}, part_out:{3}'
                                               .format(ret['dd_full_rec_in'],
                                                       ret['dd_partial_rec_in'],
                                                       ret['dd_full_rec_out'],
                                                       ret['dd_partial_rec_out']))
            self.log.debug('Done with dd, copied:{0} bytes, {1} fullrecords, {2} partrecords - '
                           'over elapsed:{3}'.format(ret['dd_bytes'],
                                                     ret['dd_full_rec_out'],
                                                     ret['dd_partial_rec_out'],
                                                     elapsed))
            self.sys('rm -f ' + str(tmpfile))
            self.sys('rm -f ' + str(tmppidfile))
        except:
            self.sys('rm -f ' + str(tmpfile))
            raise
        return ret

    def get_disk_summary(self, dfargs=None, verbose=False):
        ret = {}
        if dfargs is None:
            dfargs = "-h"
        df_info = self.get_df_info(path="", dfargs=dfargs, verbose=verbose)
        for df in df_info:
            fs = df.pop('filesystem')
            ret[fs] = df
        return ret

    def get_df_info(self, path=None, dfargs=None, verbose=False):
        """
        Return df's output in dict format for a given path.
        If path is not given will give the df info for the current working dir used in the ssh
        session this command is executed in (ie: /home/user or /root).
        path - optional -string, used to specifiy path to use in df command. Default is PWD of
                         ssh shelled command
        verbose - optional -boolean, used to specify whether or debug is printed during
                            this command.
        Example:
            dirpath = '/disk1/storage'
            dfout = self.get_df_info_at_path(path=dirpath)
            available_space = dfout['available']
            mounted_on = dfout['mounted']
            filesystem = dfout['filesystem']
        """
        ret = []
        if path is None:
            path = '${PWD}'
        else:
            if not (self.is_dir(path) or self.is_file(path)):
                raise ValueError('Provided path: "{0}" not found on system: "{1}"'
                                 .format(path, self.hostname))
        if dfargs is None:
            dfargs = ""
        else:
            if isinstance(dfargs, list):
                dfargs = " ".join(dfargs)
        cmd = 'df -P {0} {1}'.format(dfargs, path)
        if verbose:
            self.log.debug('get_df_info_at_path cmd:' + str(cmd))
        output = self.sys(cmd, code=0, verbose=verbose)
        # Get the presented fields from commands output,
        # Convert to lowercase, use this as our dict keys

        def add_underscore(grp):
            word = grp.group(0)

            return str(word).replace(" ", "_")
        field_line = str(re.sub('[A-Z]\w*(\s+)[a-z]\w*', add_underscore, output[0]))
        fields = field_line.lower().split()
        for line in output[1:]:
            line = str(line).lower().split()
            fs_dict = {}
            for field in fields:
                fs_dict[field] = line[fields.index(field)]
            ret.append(fs_dict)
        return ret

    def get_available(self, path, unit=1):
        """
        Return df output's available field. By default this is KB.
        path - optional -string.
        unit - optional -integer used to divide return value.
               Can be used to convert KB to MB, GB, TB, etc..
        """
        if not path:
            raise ValueError('Must supply path to get available disk. Got:"{0}/{1}"'
                             .format(path, type(path)))
        size = int(self.get_df_info(path=path)[0]['available'])
        return size / unit

    def assertFilePresent(self, filepath):
        '''
        Method to check for the presence of a file at 'filepath' on the instance
        filepath - mandatory - string, the filepath to verify
        '''
        filepath = str(filepath).strip()
        out = self.cmd("ls " + filepath)['status']
        self.log.debug('exit code:' + str(out))
        if out != 0:
            raise Exception("File:" + filepath + " not found on instance:" + self.id)
        self.log.debug('File ' + filepath + ' is present on ' + self.id)

    #############################################################################################
    #                   Misc Utilities
    #############################################################################################

    def put_templated_file(self, local_src, remote_dest, **kwargs):
        '''
        jinja file template aid
        '''
        tmp = tempfile.mktemp()
        try:
            render_file_template(local_src, tmp, **kwargs)
            self.ssh.sftp_put(tmp, remote_dest)
        finally:
            os.remove(tmp)
