
import array
import copy
import logging
from prettytable import PrettyTable
import re
import socket
import struct
import fcntl
import threading
from cloud_admin.access.autocreds import AutoCreds
from cloud_admin.services.serviceconnection import ServiceConnection
from cloud_admin.hosts.eucahost import EucaHost
from cloud_utils.system_utils.machine import Machine
from cloud_utils.log_utils.eulogger import Eulogger
from cloud_utils.log_utils import markup, get_traceback
from cloud_utils.net_utils.sshconnection import CommandExitCodeException


class SystemConnection(ServiceConnection):

    def __init__(self,
                 hostname,
                 username='root',
                 password=None,
                 keypath=None,
                 region_domain=None,
                 proxy_hostname=None,
                 proxy_username=None,
                 proxy_password=None,
                 proxy_keypath=None,
                 config_yml=None,
                 config_qa=None,
                 credpath=None,
                 aws_access_key=None,
                 aws_secret_key=None,
                 log_level='INFO',
                 boto_debug_level=0,
                 euca_user='admin',
                 euca_account='eucalyptus',
                 ):
        self.machine_connect_kwargs = {
            'hostname': hostname,
            'username': username,
            'password': password,
            'keypath': keypath,
            'proxy_hostname': proxy_hostname,
            'proxy_username': proxy_username or username,
            'proxy_password': proxy_password or password,
            'proxy_keypath': proxy_keypath or keypath,
            'log_level': log_level
        }
        self._clc_machine = None
        self.hostname = hostname
        self.config_qa = config_qa
        self.config_yml = config_yml
        # self._aws_access_key = aws_access_key
        # self._aws_secret_key = aws_secret_key
        self._eucahosts = {}
        self._credpath = credpath
        self.log = Eulogger(identifier=self.__class__.__name__, stdout_level=log_level)
        self.creds = AutoCreds(credpath=self._credpath,
                               region_domain=region_domain,
                               aws_access_key=aws_access_key,
                               aws_secret_key=aws_secret_key,
                               aws_account_name=euca_account,
                               aws_user_name=euca_user,
                               logger=self.log,
                               **self.machine_connect_kwargs)
        super(SystemConnection, self).__init__(hostname=hostname,
                                               aws_secret_key=self.creds.aws_secret_key,
                                               aws_access_key=self.creds.aws_access_key,
                                               logger=self.log,
                                               boto_debug_level=boto_debug_level)

    def set_loglevel(self, level, parent=False):
        """
        wrapper for log.setLevel, accept int or string.
        Levels can be found in logging class. At the time this was written they are:
        CRITICAL:50
        DEBUG:10
        ERROR:40
        FATAL:50
        INFO:20
        NOTSET:0
        WARN:30
        WARNING:30
        """
        level = level or logging.NOTSET
        if not isinstance(level, int) and not isinstance(level, basestring):
            raise ValueError('set_loglevel. Level must be of type int or string, got: "{0}/{1}"'
                             .format(level, type(level)))
        if isinstance(level, basestring):
            level = getattr(logging, str(level).upper())
        return self.log.set_parentloglevel(level)

    @property
    def clc_machine(self):
        if not self._clc_machine:
            hostname = self.machine_connect_kwargs['hostname']
            if hostname:
                #  See if a host exists matching the provided hostname
                if hostname in self.eucahosts:
                    self._clc_machine = self.eucahosts[hostname]
                #  See if this is a localhost connection
                elif self._get_clc_eucahost_for_localhost():
                    self._clc_machine = self._get_clc_eucahost_for_localhost()
                else:
                    self._clc_machine = Machine(**self.machine_connect_kwargs)
                    self.eucahosts[self.machine_connect_kwargs['hostname']] = self._clc_machine
        return self._clc_machine

    @property
    def eucahosts(self):
        if not self._eucahosts:
            self._eucahosts = self._update_host_list()
        return self._eucahosts

    def _get_clc_eucahost_for_localhost(self):
        ifaces = self._get_all_local_ip_interfaces()
        for iface, ip in ifaces:
            if ip in self.eucahosts:
                self.log.debug('CLC is bound to iface:{0} ip:{1}'.format(iface, ip))
                return self.eucahosts[ip]
        return None

    def _get_all_local_ip_interfaces(self):
        max_possible = 1028
        bytes = max_possible * 32
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        names = array.array('B', '\0' * bytes)
        outbytes = struct.unpack('iL', fcntl.ioctl(
            s.fileno(),
            0x8912,  # SIOCGIFCONF
            struct.pack('iL', bytes, names.buffer_info()[0])
        ))[0]
        namestr = names.tostring()
        interfaces = []
        for i in range(0, outbytes, 40):
            name = namestr[i:i+16].split('\0', 1)[0]
            addr   = namestr[i+20:i+24]
            ip = "{0}.{1}.{2}.{3}".format(ord(addr[0]), ord(addr[1]), ord(addr[2]), ord(addr[3]))
            interfaces.append((name, ip))
        return interfaces

    def _update_host_list(self):
        machines = self.get_all_machine_mappings()
        connect_kwargs = copy.copy(self.machine_connect_kwargs)
        if 'hostname' in connect_kwargs:
            connect_kwargs.pop('hostname')
        hostlock = threading.Lock()

        def add_host(ip, services, self=self, connect_kwargs=connect_kwargs):
            host = EucaHost(connection=self, hostname=ip, services=services, **connect_kwargs)
            with hostlock:
                self._eucahosts[ip] = host
        threads = []
        for ip, services in machines.iteritems():
            t = threading.Thread(target=add_host, args=(ip, services))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

        return self._eucahosts

    def get_host_by_hostname(self, hostname):
        return self.eucahosts.get(hostname, None)

    def get_hosts_by_service_type(self, servicetype):
        ret_list = []
        for ip, host in self.eucahosts.iteritems():
            for service in host.services:
                if service.type == servicetype:
                    ret_list.append(host)
        return ret_list

    def get_hosts_for_cloud_controllers(self):
        clc = None
        return self.get_hosts_by_service_type(servicetype='eucalyptus')

    def get_hosts_for_node_controllers(self, partition=None, instanceid=None):
        if instanceid is not None and not isinstance(instanceid, basestring):
            raise ValueError('Instance id not of string type, got:"{0}"/"{1}"'
                             .format(instanceid, type(instanceid)))
        ncs = self.get_hosts_by_service_type(servicetype='node')
        if not partition and not instanceid:
            return ncs
        retlist = []
        if instanceid:
            try:
                reservation = self.ec2_connection.get_all_instances(instance_ids=[instanceid])
            except:
                self.log.error('{0}\nFailed to find instance:"{1}" on system'
                               .format(get_traceback(), instanceid))
                return []
            if reservation:
                instance = reservation[0].instances[0]
                node_addr = instance.tags.get('euca:node')
                if node_addr:
                    for nc in ncs:
                        if nc.hostname == node_addr:
                            return [nc]
        if partition and partition in nc.partitions:
            retlist.append(nc)
        return retlist

    def get_hosts_for_cluster_controllers(self, partition=None):
        ccs = self.get_hosts_by_service_type(servicetype='cluster')
        if not partition:
            return ccs
        retlist = []
        for cc in ccs:
            if partition in cc.partitions:
                retlist.append(cc)
        return retlist

    def get_hosts_for_storage_controllers(self, partition=None):
        scs = self.get_hosts_by_service_type(servicetype='storage')
        if not partition:
            return scs
        retlist = []
        for sc in scs:
            if partition in sc.partitions:
                retlist.append(sc)
        return retlist

    def get_hosts_for_ufs(self):
        ufs = None
        return self.get_hosts_by_service_type(servicetype='user-api')


    def get_hosts_for_walrus(self):
        walrus = None
        return self.get_hosts_by_service_type(servicetype='walrusbackend')

    def show_cloud_legacy_summary(self, repo_info=True, print_method=None, file_path=None,
                                  print_table=True):
        """
        Creates a table representing the legacy Eutester/QA reprsentation of a Eucalyptus
        cloud. This can be used for legacy eutester tests, etc..
        :param repo_info: bool, if True will use the work REPO in place of Zone for the 5th column
        :param print_method: method used to print this table, defaults to self.log.info
        :param print_table: bool, if False will return the table obj
        :param file_path: string representing a local file path to save this information to
        :return: table obj if print_table is False
        """
        ret = ""
        print_method = print_method or self.log.info
        if repo_info:
            rz_col = 'REPO'
        else:
            rz_col = 'ZONE'
        pt = PrettyTable(['# HOST', 'DISTRO', 'VER', 'ARCH', rz_col, 'SERVICE CODES'])
        pt.align = 'l'
        pt.border = 0
        for ip, host in self.eucahosts.iteritems():
            split = host.summary_string.split()
            service_codes = " ".join(split[5:])
            if repo_info:
                rz_col = 'REPO'
            else:
                rz_col = split[4]
            pt.add_row([split[0], split[1], split[2], split[3], rz_col, service_codes])
            ret += "{0}\n".format(host.summary_string)
        if file_path:
            with open(file_path, 'w') as save_file:
                save_file.write(str(pt))
                save_file.flush()
        if print_table:
            print_method("\n{0}\n".format(str(pt)))
        else:
            return pt

    @staticmethod
    def vm_state_markup(state):
        if state in ['shutting-down', 'stopped', 'stopping']:
            return [1, 91]
        if state == 'terminated':
            return [1, 97]
        if state == 'running':
            return [1, 92]
        return [1, 93]

    def show_hosts(self, hosts=None, partition=None, service_type=None, serv_columns=None,
                   update=True, print_method=None, print_table=True, save_file=None):
        print_method = print_method or self._show_method
        ins_id_len = 10
        ins_type_len = 13
        ins_dev_len = 16
        ins_st_len = 15
        ins_total = (ins_id_len + ins_dev_len + ins_type_len + ins_st_len) + 5
        machine_hdr = (markup('MACHINE INFO'), 30)
        service_hdr = (markup('EUCALYPTUS SERVICES'), 90)
        pt = PrettyTable([machine_hdr[0], service_hdr[0]])
        pt.header = False
        pt.align = 'l'
        pt.hrules = 1
        pt.max_width[machine_hdr[0]] = machine_hdr[1]
        total = []
        eucahosts = {}
        if hosts is None:
            eucahosts = self.eucahosts
        elif isinstance(hosts, list):
            for host in hosts:
                eucahosts[host.hostname] = host
        elif isinstance(hosts, EucaHost):
            eucahosts[hosts.hostname] = hosts

        if not isinstance(eucahosts, dict):
            raise ValueError('show_machine_mappings requires dict example: '
                             '{"host ip":[host objs]}, got:"{0}/{1}"'
                             .format(eucahosts, type(eucahosts)))
        # To format the tables services, print them all at once and then sort the table
        # rows string into the machines columns
        try:
            sorted_ips = sorted(list(eucahosts),
                key=lambda ip: struct.unpack("!L", socket.inet_aton(ip))[0])
        except Exception as SE:
            self.log.warning('"Failed to sort host list by IP, error:"{0}"'.format(SE))
            sorted_ips = sorted(list(eucahosts))
        for hostip in sorted_ips:
            host = eucahosts[hostip]
            for serv in host.services:
                if update:
                    serv.update()
                total.append(serv)
                if serv.child_services:
                    total.extend(serv.child_services)
        # Create a table showing the service states, grab the first 3 columns
        # for type, name, state, and zone
        servpt = self.show_services(total, print_table=False)
        # Get a subset of the show services fields...
        if serv_columns is None:
            fields = servpt._field_names[0:4]
        else:
            fields = servpt._fields_names[serv_columns]
        serv_lines = servpt.get_string(border=0, padding_width=2, fields=fields).splitlines()
        header = serv_lines[0]
        ansi_escape = re.compile(r'\x1b[^m]*m')
        # Now build the machine table...
        threads = []
        hostlock = threading.Lock()

        # Method to allow host info to be gathered concurrently
        def add_host(hostip, host, self=self):
            assert isinstance(host, EucaHost)
            servbuf = header + "\n"
            mservices = []
            # Get the child services (ie for UFS)
            for serv in host.services:
                mservices.append(serv)
                mservices.extend(serv.child_services)
            for serv in mservices:
                for line in serv_lines:
                    # Remove the ansi markup for parsing purposes, but leave it in the
                    # displayed line
                    clean_line = ansi_escape.sub('', line)
                    splitline = clean_line.split()
                    if len(splitline) < 2:
                        continue
                    line_type = splitline[0]
                    line_name = splitline[1]
                    # Pull matching lines out of the pre-formatted service table...
                    if (splitline and re.match("^{0}$".format(serv.type), line_type) and
                            re.match("^{0}$".format(serv.name), line_name)):
                        # Add this line to the services to be displayed for this machine
                        if line_name not in servbuf:
                            servbuf += line + "\n"
                if serv.type == 'node':
                    if getattr(serv, 'instances', None):
                        if serv.instances:
                            vm_pt = PrettyTable([markup('INSTANCES', [1, 4]),
                                                 markup('STATE:', [1, 4]),
                                                 markup('VMTYPE:', [1, 4]),
                                                 markup('ROOT_DEV:', [1, 4])])
                            vm_pt.align = 'l'
                            vm_pt.border = 1
                            vm_pt.vrules = 2
                            vm_pt.hrules = 0
                            for x in serv.instances:
                                vm_pt.add_row([x.id,
                                               markup(x.state, self.vm_state_markup(x.state)),
                                               x.instance_type,
                                               x.root_device_type])
                            servbuf += "{0}\n".format(vm_pt)
                    av_pt = host.helpers.node_controller.show_availability_for_node(
                        print_table=False)
                    servbuf += av_pt.get_string()
            ps_sum_pt = host.show_euca_process_summary(print_table=False)
            servbuf += "\n" + ps_sum_pt.get_string(border=1, vrules=2, hrules=0)
            host_info = markup('Euca Versions:').ljust(machine_hdr[1])
            host_info += "Cloud: {0}".format(host.get_eucalyptus_version()).ljust(machine_hdr[1])
            host_info += "2ools: {0}".format(host.get_euca2ools_version()).ljust(machine_hdr[1])
            host_info += markup("Hostname:").ljust(machine_hdr[1])
            host_info += str(host.hostname).ljust(machine_hdr[1])
            sys_pt = host.show_sys_info(print_table=False)
            host_info += "{0}".format(sys_pt)
            with hostlock:
                pt.add_row([markup("HOST:") + markup(hostip, [1, 94]),
                            markup('EUCALYPTUS SERVICES:') +
                            markup('[ {0} ]'
                                   .format(" ".join(str(x) for x in host.euca_service_codes)),
                                   [1, 34])])
                pt.add_row([host_info, servbuf])

        for hostip, host in eucahosts.iteritems():
            t = threading.Thread(target=add_host, args=(hostip, host))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        if save_file:
            with open(save_file, 'w') as sf:
                sf.write("\n{0}\n".format(pt.get_string()))
        if print_table:
            # print_method("\n{0}\n".format(pt.get_string(sortby=pt.field_names[1])))
            print_method("\n{0}\n".format(pt.get_string()))
        else:
            return pt

    def upgrade_cloud(self, network_mode=None, ccs=None, ncs=None, clcs=None, scs=None, ufs=None,
                      ws=None, gpgcheck=False,  yum_arg_list=None, dry_run=False, rerun=False):
        if rerun:
            if not hasattr(self, '_upgrade_dict'):
                raise ValueError('self._upgrade_dict not found, can not use "rerun"')
            return self.upgrade_cloud(**self._upgrade_dict)
        if yum_arg_list is None:
            yum_arg_list = []
        if not isinstance(yum_arg_list, list):
            yum_arg_list = [yum_arg_list]
        if not gpgcheck:
            yum_arg_list.append("--nogpg")
        yum_args = " -y {0}".format(" ".join(yum_arg_list))
        # Sort out the host machines by services...
        known_net_modes = ['EDGE', 'VPCMIDO', 'MANAGED']
        if network_mode is None:
            try:
                cluster_name = self.get_all_cluster_names()[0]
                prop = self.get_property("{0}.cluster.networkmode".format(cluster_name))
                network_mode = prop.value
            except:
                self.log.error('Could not retrieve network mode for cloud')
                raise
        if re.search('MANAGED', network_mode):
                    network_mode = 'MANAGED'
        if network_mode not in known_net_modes:
            raise ValueError('Unknown network mode:{0}, known types {1}'
                             .format(network_mode, ", ".join(known_net_modes)))
        # service arrays
        eucalyptus_cloud_hosts = []
        eucanetd_hosts = []

        ccs = ccs or self.get_hosts_for_cluster_controllers()
        ncs = ncs or self.get_hosts_for_node_controllers()
        clcs = clcs or self.get_hosts_for_cloud_controllers()
        scs = scs or self.get_hosts_for_storage_controllers()
        ufs = ufs or self.get_hosts_for_ufs()
        ws = ws or self.get_hosts_for_walrus()

        upgrade_dict = {'network_mode': network_mode, 'ccs': ccs, 'ncs': ncs,
                        'clcs': clcs, 'scs': scs, 'ufs': ufs, 'ws': ws, 'gpgcheck': gpgcheck,
                        'yum_arg_list': yum_arg_list}
        if dry_run:
            return upgrade_dict
        for host in clcs + ufs + scs + ws:
            if host not in eucalyptus_cloud_hosts:
                eucalyptus_cloud_hosts.append(host)
        if network_mode == "MANAGED":
            eucanetd_hosts = ccs
        elif network_mode == 'EDGE':
            eucanetd_hosts = ncs
        elif network_mode == 'VPCMIDO':
            eucanetd_hosts = clcs
        else:
            raise ValueError('Unsupported network mode: "{0}"'.format(network_mode) )

        def stop_service(host, service, timeout=300):
            try:
                host.sys('service {0} stop'.format(service), code=0, timeout=timeout)
            except CommandExitCodeException as CE:
                if CE.status == 2:
                    # service is already stopped
                    pass
                else:
                    raise
        try:
            # Shutdown all the Eucalyptus cloud services...
            self.log.info('Beginning upgrade. Shutting down all cloud services now...')
            for host in clcs:
                stop_service(host, 'eucalyptus-cloud')
            for host in eucalyptus_cloud_hosts:
                # Skip the CLCs which have already been stopped
                if host not in clcs:
                    stop_service(host, 'eucalyptus-cloud')
            for host in ccs:
                stop_service(host, 'eucalyptus-cc')
            for host in ncs:
                stop_service(host, 'eucalyptus-nc')
            for host in eucanetd_hosts:
                stop_service(host, 'eucanetd')

            # Upgrade packages...
            self.log.info('Upgrading Eucalyptus packages on all hosts')
            for host in self.eucahosts.itervalues():
                host.sys('yum upgrade eucalyptus {0}'.format(yum_args), code=0, timeout=400)
            self.log.info('Package upgrade complete, restarting cloud services now...')
            # Start all the Eucalyptus cloud services...
            # Do the CLCs first than the other Java/Cloud services
            self.log.info('Starting CLCs...')
            for host in clcs:
                host.sys('service eucalyptus-cloud start', code=0, timeout=300)
            self.log.info('Starting remaining Java Components...')
            for host in eucalyptus_cloud_hosts:
                # Skip the CLCs which have already been started
                if host not in clcs:
                    host.sys('service eucalyptus-cloud start', code=0, timeout=300)
            self.log.info('Starting Cluster Controllers...')
            for host in ccs:
                host.sys('service eucalyptus-cc start', code=0, timeout=300)
            self.log.info('Starting Node Controllers...')
            for host in ncs:
                host.sys('service eucalyptus-nc start', code=0, timeout=300)
            self.log.info('Starting Eucanetd...')
            for host in eucanetd_hosts:
                host.sys('service eucanetd start', code=0, timeout=300)
            self.log.info('Upgrade Done')
        except:
            self.log.error('Upgrade failed. The upgrade params are found in self._upgrade_dict.'
                           'These can be used via the "rerun" argument to rerun this upgrade'
                           'using the same environment/machines')
            raise
        finally:
            # write to this dict for before/after comparison of the cloud after upgrade
            self._upgrade_dict = upgrade_dict





    def build_machine_dict_from_config(cls):
        raise NotImplementedError()

    def build_machine_dict_from_cloud_services(self):
        raise NotImplementedError('not yet implemented')
