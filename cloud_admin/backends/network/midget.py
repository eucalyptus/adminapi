from midonetclient.api import MidonetApi
from midonetclient import api_lib
from midonetclient import exc as mido_exc
from webob import exc
from midonetclient.api_lib import http_errors, from_json
from midonetclient.router import Router
from midonetclient import resource_base
from midonetclient import vendor_media_type
from midonetclient.bridge import Bridge
from midonetclient.chain import Chain
from midonetclient.host import Host
from midonetclient.host_interface_port import HostInterfacePort
from midonetclient.host_interface import HostInterface
from midonetclient.ip_addr_group import IpAddrGroup
from cloud_utils.net_utils import is_address_in_network, sshconnection
from cloud_utils.log_utils import markup, get_traceback
from cloud_utils.log_utils import BackGroundColor, TextStyle, ForegroundColor
from cloud_utils.log_utils.eulogger import Eulogger
from cloud_utils.system_utils.machine import Machine
from cloud_admin.systemconnection import SystemConnection
from boto.ec2.group import Group as BotoGroup
from boto.ec2.instance import Instance
from boto.ec2.securitygroup import SecurityGroup, IPPermissions
from ConfigParser import ConfigParser, NoOptionError, NoSectionError
from httplib import CannotSendRequest
from io import StringIO
from json import loads as json_loads
from kazoo.client import KazooClient
from prettytable import PrettyTable
import json
import socket
import time
import urllib
import re
import copy



class ArpTable(resource_base.ResourceBase):
    def __init__(self, uri, dto, auth):
        super(ArpTable, self).__init__(uri, dto, auth)

    def get_ip(self):
        return self.dto.get('ip')

    def get_mac(self):
        return self.dto.get('mac')

    def get_macaddr(self):
        return self.dto.get('macAddr')


class MacTable(resource_base.ResourceBase):
    def __init__(self, uri, dto, auth):
        super(MacTable, self).__init__(uri, dto, auth)

    def get_port_id(self):
        return self.dto.get('portId')

    def get_bridge_id(self):
        return self.dto.get('bridgeId')

    def get_vlan_id(self):
        return self.dto.get('vlanId')

    def get_macaddr(self):
        return self.dto.get('macAddr')


class Midget(object):
    '''
    Midonet get or primarily read-only agent used for getting status and describing the system for
    the purposes of debugging and mapping output to a Eucalyptus cloud's usage of it.
    '''
    _CHAIN_JUMP = 107
    _ADDR_SPACING = 22

    def __init__(self, midonet_api_host, midonet_api_port='8080', midonet_username=None,
                 midonet_password=None, clc_ip=None, clc_password=None, systemconnection=None,
                 clc_tunnel=True, clc_tunnel_host='127.0.0.1', mido_log_level='INFO',
                 euca_log_level='INFO'):
        """

        :param midonet_api_host: IP/hostname of machine serving midonet api
        :param midonet_api_port: tcp port for midonet api
        :param midonet_username: midonet api login username
        :param midonet_password: midonet api login password
        :param clc_ip: IP/Hostname of Eucalyptus CLC used to create a euca SystemConnection().
        :param clc_password: ssh password of Eucalyptus CLC (if not using ssh key)
        :param systemconnection: A Eucalyptus System Connection object.
        :param clc_tunnel: Bool, if true will tunnel mido http requests through CLC.
        :param clc_tunnel_host: ip/hostname to use for tunneled api host destination, default is
                                '127.0.0.1' relative to the CLC.
        :param mido_log_level: Loglevel for this mid-get object
        :param euca_log_level: Loglevel used if 'creating' a euca systemconnection object.
        """
        self.midonet_api_host = midonet_api_host
        self.midonet_api_port = midonet_api_port
        self.midonet_username = midonet_username
        self.midonet_password = midonet_password
        self._host_connections = {}

        self.log = Eulogger(identifier='MidoDebug:{0}'.format(self.midonet_api_host),
                            stdout_level=mido_log_level,
                            parent_logger_name=self.__class__.__name__)
        if clc_tunnel:
            clc_ip = clc_ip or midonet_api_host
            self.midonet_api_host = clc_tunnel_host
            api_lib.do_request = self.tunneled_request
        self.mapi = MidonetApi(base_uri='http://{0}:{1}/midonet-api'
                               .format(self.midonet_api_host, self.midonet_api_port),
                               username=self.midonet_username, password=self.midonet_password)
        self.eucaconnection = systemconnection
        if not self.eucaconnection:
            clc_ip = clc_ip
            self.eucaconnection = SystemConnection(hostname=clc_ip, password=clc_password,
                                                   log_level=euca_log_level)

        self.default_indent = ""
        self._euca_instances = {}
        self._protocols = {}

    def debug(self, msg):
        self.log.debug(msg)

    def info(self, msg):
        self.log.info(msg)

    def set_mido_log_level(self, level):
        """
        Sets the log level on the mid-get operations
        note the parent log level may also need to be adjusted.
        To adjust the parent logger, use: self.set_euca_loglevel,
        or set directly self.log.parent...
        :param level: logging level integer or name (debug, info, etc)
        :return:
        """
        self.log.set_stdout_loglevel(level)

    def set_euca_parent_log_level(self, level):
        level = self.log.format_log_level(level, default=None)
        if level is None:
            raise ValueError('Unknown and/or invalid log level: "{0}"'.format(level))
        self.log.parent.level = level

    def tunneled_request(self, uri, method, body=None, query=None, headers=None,
                         ssh_host=None, depth=0, max_redirects=5, *args, **kwargs):
        """Process a http rest request with input and output json strings.

        Sends json string serialized from body to uri with verb method and returns
        a 2-tuple made of http response, and content deserialized into an object.
        :param uri: URI of request http://addr/path etc
        :param method: http method, GET, POST, etc
        :param body: option body of request
        :param query: query params, dict
        :param headers: headers, dict
        :param ssh_host: An SshConnection obj to tunnel requests through. Default is the CLC.
        :param depth: current amount of redirects for this request
        :param max_redirects: max amount of redirects allowed for this request
        :return: (http response obj, data as json).
        """
        if depth > max_redirects:
            raise ValueError('Request detph:{0} has exceed max_redirects:{1}, uri:{2}'
                             .format(depth, max_redirects, uri))
        ssh_host = ssh_host or self.eucaconnection.clc_machine.ssh
        if not ssh_host:
            raise ValueError('tunneled request requires an SshConnection. None provided and '
                             'could not find clc ssh host in self.eucaconnection')
        elif not isinstance(ssh_host, sshconnection.SshConnection):
            raise ValueError('ssh_host must be of type SshConnection, got: "{0}/{1}'
                             .format(ssh_host, type(ssh_host)))
        query = query or dict()
        headers = headers or dict()
        response = None
        content = None
        status = -1
        self.log.debug("tunneled request: uri=%s, method=%s" % (uri, method))
        self.log.debug("tunneled request: body=%s" % body)
        self.log.debug("tunneled request: headers=%s" % headers)
        if query:
            uri += '?' + urllib.urlencode(query)
        data = json.dumps(body) if body is not None else '{}'

        try:
            response = ssh_host.http_fwd_request(url=uri, method=method, body=data,
                                                 headers=headers)
            content = response.read()
            status = response.status
        except socket.error as serr:
            if serr[1] == "ECONNREFUSED":
                raise mido_exc.MidoApiConnectionRefused()
            raise
        except CannotSendRequest as CSE:
            self.log.error('{0}\nCould not send request to midonet-api, err:"{1}"'
                           .format(get_traceback(), CSE))
            raise mido_exc.MidoApiConnectionRefused()

        self.log.debug("do_request: response=%s | content=%s" % (response, content))
        if int(status == 302):
            self.log.info('302 response')
            location = response.getheader('location')
            if location and location != uri:
                self.log.info('Redirecting: to url:{0}'.format(location))
                depth += 1
                return self.tunneled_request(uri=location, method=method,
                                             body=body, query=query, headers=headers,
                                             ssh_host=ssh_host, depth=depth,
                                             max_redirects=max_redirects)
        if int(status) > 400:
            error = http_errors.get(str(status), None)
            if not error:
                error = RuntimeError
            self.log.error("Got http error(response=%r, content=%r) for "
                           "request(uri=%r, method=%r, body=%r, query=%r,headers=%r). "
                           "Raising exception=%r" % (response, content, uri, method, body,
                                                     query, headers, error))
            raise error
        return response, from_json(content)

    def mido_cli_cmd(self, cmd, ssh=None, midonet_url='http://127.0.0.1:8080/midonet-api',
                     listformat=True, verbose=True, no_auth=True, username=None, password=None,
                     tenant=None):
        """
        Attempts to execute a midocli command on a remote ssh connected machine and
        return the results

        :return:
        :param cmd: a string representing the command to feed to midocli
        :param ssh: a adminapi net_utils.sshconnection object
        :param midonet_url: url to be fed to midocli
        :param no_auth: if true will pass no_auth flag to midonet
        :param verbose: bool, set verbose flag for underlying ssh sys command
        :param listformat: bool, if true returns list of lines else a single string buffer
        :param username: username for midonet auth
        :param password: password for midonnet auth
        :param tenant: midonet tenantid, uuid
        :return: output from command
        """
        try:
            ssh = ssh or self.eucaconnection.clc_machine.ssh
        except:
            raise ValueError('sshconnection object was not provided and not found in the'
                             'local eucaconnection object')
        command_prefix = 'midonet-cli --midonet-url={0} '.format(midonet_url)
        if no_auth:
            command_prefix += ' --no-auth '
        if username:
            command_prefix += ' --user={0} '.format(username)
        if password:
            command_prefix += ' --password={0} '.format(password)
        if tenant:
            command_prefix += ' --tenant={0} '.format(tenant)

        cmd = command_prefix + str(cmd)
        return ssh.sys(cmd=cmd, listformat=listformat, verbose=verbose)


    def _indent_table_buf(self, table, indent=None):
        """
        Used to offset a table when printed
        :param table: Prettytable obj
        :param indent: string to prepend as indentation
        :return: string buffer
        """
        if indent is None:
            indent = self.default_indent
        buf = str(table)
        ret_buf = ""
        for line in buf.splitlines():
            ret_buf += '{0}{1}\n'.format(indent, line)
        return ret_buf

    def _link_table_buf(self, table, indent=4):
        """
        Created an ascii arrow or link to a table within a table.
        This is used when a row within a table needs to be expanded into a sub-table.
        :param table: pretty table obj
        :param indent: int, number of spaces to indent
        :return: resulting table string/buffer
        """
        if not table:
            return None
        if indent < 2:
            indent = 2
        preline = ""
        linkpoint = ""
        linkline = "{0}\n".format(self._bold("|", 103))
        for x in xrange(0, indent - 1):
            linkpoint += "-"
        for x in xrange(0, indent + 1):
            preline += " "
        linkline += self._bold("+{0}>".format(linkpoint), 103)
        lines = str(table).splitlines()
        ret_buf = "{0}{1}\n".format(linkline, lines[0])
        for line in lines[1:]:
            ret_buf += '{0}{1}\n'.format(preline, line)
        return ret_buf

    def _errmsg(self, text):
        """
        Used for logging errors with ascii markups.
        :param text: msg to be logged.
        """
        self.log.error(markup(text, [TextStyle.BOLD, ForegroundColor.RED]))

    def _header(self, text):
        return markup(text=text, markups=[TextStyle.BOLD, ForegroundColor.BLUE])

    def _bold(self, text, value=1):
        return markup(text=text, markups=[TextStyle.BOLD])

    def _highlight_buf_for_instance(self, buf, instance):
        """
        Highlight substrings that match information contained in a boto instance obj.
        :param buf: string buffer
        :param instance: boto instance obj
        :return: marked up string buffer
        """
        ret_buf = ""
        for line in str(buf).splitlines():
            searchstring = "{0}|{1}|{2}".format(instance.id,
                                                instance.private_ip_address,
                                                instance.ip_address)
            try:
                searchstring = "{0}|{1}".format(
                    searchstring,
                    self.eucaconnection.ec2_connection.get_all_subnets(
                        instance.subnet_id)[0].cidr_block)
            except:
                pass
            for match in re.findall(searchstring, line):
                line = line.replace(match, self._bold(match, 102))
            ret_buf += line + "\n"
        return ret_buf

    @property
    def protocols(self):
        '''
        Dict mapping of ip protocol names to numbers
        :return: dict
        '''
        if not self._protocols:
            proto_dict = {}
            for attr in dir(socket):
                if attr.startswith('IPPROTO_'):
                    proto_dict[str(getattr(socket, attr))] = attr.replace('IPPROTO_', '').upper()
            self._protocols = proto_dict
        return self._protocols

    def _get_protocol_name_by_number(self, number):
        # look up protocol by number, return protocol name or just give the number back
        return self.protocols.get(str(number), str(number))

    def _get_instance(self, instance):
        """
        Sanitize a value (ie usually an instance id or an instance obj) to return an
        instance obj
        :param instance: value to be checked, and or converted to a boto instance
        :return: boto instance
        """
        fetched_ins = None
        if not isinstance(instance, Instance):
            if isinstance(instance, basestring):
                fetched_ins = self._get_instance_by_id(id=instance)
            else:
                raise ValueError('instance not type boto Instance nor instance id string. '
                                 'instance: "{0}:{1}"'.format(instance, type(instance)))
            if not fetched_ins:
                raise ValueError('Could not find instance {0} on system'.format(instance))
            instance = fetched_ins
        return instance

    def ping_instance_private_ip_from_euca_internal(self,
                                                    instance,
                                                    proxy_machine=None,
                                                    net_namespace=None,
                                                    verbose=False,
                                                    ping_timeout=5):
        """
        Attempts to ping instance from network namespace on the Machine hosting the underlying
        midonet gateway (likely the Euca CLC).

        :param instance: boto instance obj or instance id
        :param proxy_machine: cloud_utils Machine() obj, will default to CLC
        :param net_namespace: string for network namespace, will default to instance.vpc_id
        :param verbose: bool to log info
        :param ping_timeout: time allowed when running ping cmd on proxy
        :return: ping command's exit status
        """
        instance = self._get_instance(instance)
        if not proxy_machine:
            proxy_machine = self.eucaconnection.clc_machine
        net_namespace = net_namespace or instance.vpc_id

        out = proxy_machine.ping_check(instance.private_ip_address,
                                       net_namespace=net_namespace,
                                       verbose=verbose)
        status = out.get('status', None)
        if status == 0:
            statusmsg = 'Success(0)'
        else:
            statusmsg = 'Failed({0})'.format(status)
        self.info('\nCmd:"{0}", output:\n{1}\n{2} pinging instance: {3},  private ip:{4} '
                  'from internal host: {5}'.format(out.get('cmd', None), out.get('output', None),
                                                   statusmsg, instance.id,
                                                   instance.private_ip_address,
                                                   proxy_machine.hostname))
        return status

    def dump_euca_gateway_info_for_instance(self, instance, proxy_machine=None,
                                            net_namespace=None, loglevel='debug'):
        """
        Debug method to provide potentially helpful info from current machine when debugging
        connectivity issues.
        :param instance: A boto instance obj, or instance id to gather info for.
        :param net_namespace: the network namespace to gather info from. Will attempt to derive
                              from the instance if not provided.
        :param proxy_machine: Machine to grab info from. Likely the midonet gw for this instance.
        :param loglevel: the python logging attribute to use. Loglevel of None or 0 is no logging.
        :return string buf containing the dumped network info.
        """
        instance = self._get_instance(instance)
        if not proxy_machine:
            proxy_machine = self.eucaconnection.clc_machine
        net_namespace = net_namespace or instance.vpc_id
        buf = ('Dumping info for instance: "{0}",  private ip:"{1}" from Mido machine: "{2}"'
               .format(instance.id, instance.private_ip_address, proxy_machine.hostname))
        buf += ('Fetching network debug info from internal host...')
        buf += proxy_machine.dump_netfail_info(ip=instance.private_ip_address,
                                               net_namespace=net_namespace, loglevel=None)
        buf += ('Done fetching/logging network debug info from internal euca proxy host'
                'for instance {0}, private ip: {1}, from internal host: {2}'
                .format(instance.id, instance.private_ip_address, proxy_machine.hostname))
        if loglevel:
            logger = getattr(self.log, loglevel, None)
            if logger:
                logger(buf)
        return buf

    def get_all_routers(self, search_dict={}, eval_op=re.search, query=None):
        """
        Returns all routers that have attributes and attribute values as defined in 'search_dict'
        """
        routers = self.mapi.get_routers(query=None)
        remove_list = []
        for key in search_dict:
            for router in routers:
                if hasattr(router, key):
                    try:
                        if eval_op(str(search_dict[key]), router.dto.get(key)):
                            continue
                    except:
                        self.info('Error while evaluating -> {0}("{1}","{2}")'
                                  .format("{0}.{1}".format(getattr(eval_op, "__module__", ""),
                                                           getattr(eval_op, "__name__", "")),
                                          str(search_dict[key]),
                                          str(getattr(router, key))))
                        raise
                remove_list.append(router)
            for router in remove_list:
                if router in routers:
                    routers.remove(router)
        return routers

    def get_router_for_instance(self, instance):
        """
        Fetch the midonet router obj for this instance
        :param instance: either instance id or boto instance obj
        :return: mido router obj
        """
        instance = self._get_instance(instance)
        self.info('Getting router for instance:{0}, vpc:{1}'.format(instance.id, instance.vpc_id))
        routers = self.get_all_routers(search_dict={'name': instance.vpc_id})
        if len(routers) != 1:
            raise ValueError('Expected to find 1 matching router for instance:{0}, found:{1}'
                             .format(instance.id, routers))
        router = routers[0]
        self.info('Found router:{0} for instance:{1}'.format(router.get_name(), instance.id))
        return router

    def get_router_by_name(self, name):
        """
        Fetch a midonet router by it's name
        :param name: string, name of router
        :return: mido router obj or None
        """
        assert name
        search_string = "^{0}$".format(name)
        self.info('Using Search String:{0}'.format(search_string))
        routers = self.get_all_routers(search_dict={'name': search_string}, eval_op=re.match)
        if routers:
            return routers[0]
        return None

    def show_routers_brief(self, routers=None, showchains=False, printme=True):
        """
        Show a list of of routers, or by default all routers available in the current session
        context. Use show_routers to display the route information of each router.
        """
        if routers is None:
            routers = self.get_all_routers()
        if not isinstance(routers, list):
            routers = [routers]
        headers = ['Name', 'AdminState', 'ID', 'T-ID']
        if showchains:
            headers.extend(['InboundChain', 'OutboundChain'])
        pt = PrettyTable(headers)
        for router in routers:
            row = [router.get_name(), router.get_admin_state_up(), router.get_id(),
                   router.get_tenant_id()]
            if showchains:
                row.extend([router.get_inbound_filter_id(), router.get_outbound_filter_id()])
            pt.add_row(row)
        if printme:
            self.info('\n{0}\n'.format(pt))
        else:
            return pt

    def show_routes(self, routes, printme=True):
        '''
        show a list of provided route objects
        '''
        if not isinstance(routes, list):
            routes = [routes]
        pt = PrettyTable(['Destination', 'Source', 'nexthopGW', 'nexthop', 'weight', 'ID'])
        for route in routes:
            pt.add_row(['{0}/{1}'.format(route.get_dst_network_addr(),
                                         route.get_dst_network_length()),
                        '{0}/{1}'.format(route.get_src_network_addr(),
                                         route.get_src_network_length()),
                        route.get_next_hop_gateway(),
                        route.get_next_hop_port(),
                        route.get_weight(),
                        route.get_id()])
        if printme:
            self.info('\n{0}\n'.format(pt))
        else:
            return pt

    def show_routers(self, routers=None, loglevel='info', printme=True):
        '''
        Show a list of routers, or by default all routers in the current session context
        :param loglevel: local logger method to use to print the router info, or None
        :param routers: either a string 'name of router' or list of router objects.
        :return if loglevel is None, the buffer contain router info is returned. Else
                the table is printed with the local logger's method 'loglevel'.
        '''
        printmethod = None
        if printme:
            if loglevel:
                assert isinstance(loglevel, basestring), "loglevel must be type string or None"
                loglevel = str(loglevel).lower()
                printmethod = getattr(self.log, loglevel, None)
            if not printmethod:
                def printmethod(x):
                    print x
        buf = ""
        if routers is None:
            routers = self.get_all_routers()
        elif isinstance(routers, basestring):
            router = self.get_router_by_name(routers)
            if not router:
                raise ValueError('Router by name:"{0}" not found'.format(routers))
            routers = [router]
        if not isinstance(routers, list):
            routers = [routers]
        for router in routers:
            if router:
                buf += "\n{0}\n".format(self.show_router_summary(router,
                                                                showchains=False,
                                                                printme=False))
        if printmethod:
            printmethod(buf)
        else:
            return buf

    def show_router_summary(self, router, showchains=True, indent=None, printme=True):
        """
        Show a single routers summary
        """
        if indent is None:
            indent = self.default_indent
        if isinstance(router, basestring):
            r = self.get_router_by_name(router)
            if not r:
                raise ValueError('Router by name:"{0}" not found'.format(router))
            router = r
        title = self._header("ROUTER:{0}".format(router.get_name()))
        pt = PrettyTable([title])
        pt.align[title] = 'l'
        pt.padding_width = 0

        buf = self._bold("{0}ROUTER SUMMARY:\n".format(indent), 4)
        buf += self._indent_table_buf(self.show_routers_brief(routers=[router], printme=False))
        buf += self._bold("{0}ROUTES:\n".format(indent), 4)
        buf += self._indent_table_buf(self.show_routes(routes=router.get_routes(), printme=False))
        buf += self._bold("{0}ROUTER PORTS:\n".format(indent), 4)
        buf += self._indent_table_buf(self.show_ports(ports=router.get_ports(), printme=False))
        if showchains:
            if router.get_inbound_filter_id():
                in_filter_id = str(router.get_inbound_filter_id())
                in_filter = self.mapi.get_chain(in_filter_id)
                buf += "\n" + self._bold("{0}ROUTER INBOUND FILTER ({1}):\n"
                                         .format(indent, in_filter_id), 4)
                buf += self._indent_table_buf(self.show_chain(chain=in_filter, printme=False))
            if router.get_outbound_filter_id():
                out_filter_id = str(router.get_outbound_filter_id())
                out_filter = self.mapi.get_chain(out_filter_id)
                buf += "\n" + self._bold("{0}ROUTER OUTBOUND FILTER ({1}):\n"
                                         .format(indent, out_filter_id), 4)
                buf += self._indent_table_buf(self.show_chain(chain=out_filter, printme=False))
        pt.add_row([buf])
        if printme:
            self.info('\n{0}\n'.format(pt))
        else:
            return pt

    def get_device_by_peer_id(self, peerid):
        device = None
        port = self.mapi.get_port(peerid)
        type = str(port.get_type()).upper()
        if type == 'BRIDGE':
            device = self.mapi.get_bridge(port.get_device_id())
        if type == 'ROUTER':
            device = self.mapi.get_router(port.get_device_id())
        if not device:
            raise ValueError('Unknown device type for peerid:{0}, port:{1}, type:{2}'
                             .format(peerid, port.get_id(), port.get_type()))
        return device

    def get_router_port_for_subnet(self, router, cidr):
        assert cidr
        for port in router.get_ports():
            network = "{0}/{1}".format(port.get_network_address(), port.get_network_length())
            if str(network) == str(cidr):
                return port
        return None

    def get_bridge_for_instance(self, instance):
        instance = self._get_instance(instance)
        router = self.get_router_for_instance(instance)
        if not router:
            raise ValueError('Did not find router for instance:{0}'.format(instance.id))
        subnet = self.eucaconnection.ec2_connection.get_all_subnets(
            subnet_ids=['verbose', instance.subnet_id])[0]
        if not subnet:
            raise ValueError('Did not find subnet for instance:{0}, subnet id:{1}'
                             .format(instance.id, instance.subnet_id))
        port = self.get_router_port_for_subnet(router, subnet.cidr_block)
        if not port:
            raise ValueError('Did not find router port for instance:{0}, subnet:{1}'
                             .format(instance.id, subnet.cidr_block))
        bridge = self.get_device_by_peer_id(port.get_peer_id())
        if not isinstance(bridge, Bridge):
            raise ValueError('peer device for instance router is not a bridge, '
                             'fix the assumptions made in this method!')
        return bridge

    def show_port_summary(self, port, showchains=True, showbgp=True, indent=None, printme=True):
        if indent is None:
            indent = self.default_indent
        title = self._bold("PORT SUMMARY FOR PORT:{0}".format(port.get_id()), 94)
        titlept = PrettyTable([title])
        titlept.align[title] = 'l'
        buf = self._bold("{0}PORT INFO:\n".format(indent), 4)
        pt = PrettyTable(['PORT ID', 'BGPS', 'IPADDR', 'NETWORK', 'MAC',
                          'TYPE', 'UP', 'PEER ID'])
        pt.align['PEER ID'] = 'l'
        pt.max_width['PEER ID'] = 20
        bgps = 0
        try:
            if port.dto.get('bgps'):
                bgps = port.get_bgps()
                if bgps:
                    bgps = len(bgps)
                else:
                    bgps = 0
        except Exception, E:
            bgps = 'ERROR'
            self.info('Error fetching bgps from port:{0}, err"{1}'.format(port.get_id(), E))

        pt.add_row([port.get_id(),
                    bgps,
                    port.get_port_address(),
                    "{0}/{1}".format(port.get_network_address(), port.get_network_length()),
                    port.get_port_mac(),
                    port.get_type(),
                    port.get_admin_state_up(),
                    port.get_peer_id()])
        buf += self._indent_table_buf(str(pt))
        if showbgp and bgps:
            buf += self._bold("{0}PORT BGP INFO:\n".format(indent), 4)
            buf += self._indent_table_buf(str(self.show_bgps(port.get_bgps() or [], printme=False)))
        if showchains:
            if port.get_inbound_filter_id():
                in_filter = self.mapi.get_chain(str(port.get_inbound_filter_id()))
                buf += self._bold("{0}PORT INBOUND FILTER:".format(indent), 4)
                buf += "\n"
                buf += self._indent_table_buf(self.show_chain(chain=in_filter, printme=False))
            if port.get_outbound_filter_id():
                out_filter = self.mapi.get_chain(str(port.get_outbound_filter_id()))
                buf += self._bold("{0}PORT OUTBOUND FILTER:".format(indent), 4)
                buf += "\n"
                buf += self._indent_table_buf(self.show_chain(chain=out_filter, printme=False))
        titlept.add_row([buf])
        if printme:
            self.info('\n{0}\n'.format(titlept))
        else:
            return titlept

    def show_ports(self, ports, verbose=True, printme=True):
        """
        Show formatted info about a list of ports or a specific port.
        For more verbose info about a specific port use show_port_summary()
        """
        buf = ""
        pt = None
        if ports:
            if not isinstance(ports, list):
                ports = [ports]
            for port in ports:
                if pt is None:
                    if buf:
                        buf += "(PORTS TABLE CONTINUED...)\n"
                    pt = PrettyTable(['PORT ID', 'BGPS', 'IPADDR', 'NETWORK', 'MAC',
                                          'TYPE', 'UP', 'PEER ID'])
                    pt.padding_width = 0
                bgps = 0
                try:
                    if port.dto.get('bgps'):
                        bgps = port.get_bgps()
                        if bgps:
                            bgps = len(bgps)
                        else:
                            bgps = 0
                except Exception, E:
                    bgps = 'ERROR'
                    self.info('Error fetching bgps from port:{0}, err"{1}'
                              .format(port.get_id(), E))
                pt.add_row([port.get_id(),
                            bgps,
                            port.get_port_address(),
                            "{0}/{1}".format(port.get_network_address(),
                                             port.get_network_length()),
                            port.get_port_mac(),
                            port.get_type(),
                            port.get_admin_state_up(),
                            port.get_peer_id()])
                outbound_filter_id = port.get_outbound_filter_id()
                inbound_filter_id = port.get_inbound_filter_id()
                # Append bgp and filter to table
                if (bgps and bgps != "ERROR") or (verbose and
                                                      (outbound_filter_id or inbound_filter_id)):
                    lines = []
                    for line in str(pt).splitlines():
                        line = line.strip()
                        if line:
                            lines.append(line)
                    # footer = lines[-1]
                    buf += "\n".join(lines) + '\n'
                    pt = None
                    if outbound_filter_id:
                        buf += self._link_table_buf(
                            "PORT:{0} OUTBOUND FILTER:\n{1}"
                                .format(port.get_id(),
                                        self.show_chain(self.mapi.get_chain(outbound_filter_id),
                                                        printme=False)))
                    if inbound_filter_id:
                        buf += self._link_table_buf(
                            "PORT:{0} INBOUND FILTER:\n{1}"
                                .format(port.get_id(),
                                        self.show_chain(self.mapi.get_chain(inbound_filter_id),
                                                        printme=False)))
                    if bgps:
                        buf += self._link_table_buf(self.show_bgps(port.get_bgps(), printme=False))

            if pt:
                buf += str(pt) + '\n'
        if printme:
            self.info('\n{0}\n'.format(buf))
        else:
            return buf

    def show_bgp_hosts_for_euca_router(self, router_name='eucart', printmethod=None, printme=True):
        ret_buf = ""
        router = self.get_router_by_name(router_name)
        bgp_ports = []
        for port in router.get_ports():
            if port.get_bgps():
                bgp_ports.append(port)
        bgp_hosts = []
        for port in bgp_ports:
            host = self.mapi.get_host(port.get_host_id())
            if host:
                bgp_hosts.append(host)
            else:
                self.log.error('No host found for port:{0} using host_id:{1}'
                               .format(port.get_id(), port.get_host_id()))
            port_table = str(self.show_port_summary(port=port, printme=False))
            host_table = self.show_hosts(host, printme=False)
            ret_buf += "\n{0}\n\n{1}\n{2}\n"\
                .format("#".ljust(len(port_table.splitlines()[0]), "#"), port_table, host_table)
        if printme:
            printmethod = printmethod or self.log.info
            printmethod("\n{0}\n".format(ret_buf))
        else:
            return ret_buf

    def show_bgps(self, bgps, printme=True):
        buf = ""
        mainpt = PrettyTable(['BGP INFO'])
        mainpt.header = False
        mainpt.align = 'l'
        mainpt.vrules = 0
        mainpt.hrules = 0
        if not isinstance(bgps, list):
            bgps = [bgps]
        port = None
        host = None
        bgp_id = None
        pt = None
        for bgp in bgps:
            port_id = bgp.dto.get('portId')
            if not port or port.get_id() != port_id:
                port = self.mapi.get_port(port_id)
                host_id = port.get_host_id()
                if host_id:
                    host = self.mapi.get_host(port.get_host_id())
                    hostname = host.get_name()
                else:
                    host = None
                    hostname = None
            interface_name = port.get_interface_name()

            port_header = 'BGP INFO FOR PORT:'.format(port_id)
            pt = PrettyTable([port_header, 'BGP ID', 'PEER ADDR',
                                  'LOCAL AS', 'PEER AS', 'AD ROUTES'])
            pt.max_width[port_header] = len(port_id) or len('BGP INFO FOR PORT:')
            pt.align[port_header] = 'l'
            pt.add_row([port_id,
                        bgp.get_id(),
                        bgp.get_peer_addr(),
                        bgp.get_local_as(),
                        bgp.get_peer_as(),
                        "\n".join(self._format_ad_routes(bgp.get_ad_routes()) or [])])
            # Create a status table for formatting
            status_pt = PrettyTable(['PORT HOST:{0} ({1} : {2} : {3}/{4})'
                                     .format(hostname,
                                             interface_name,
                                             port.get_port_address(),
                                             port.get_network_address(),
                                             port.get_network_length())])
            status_pt.align = 'l'
            status_pt.vrules = 2
            status_pt.hrules = 3
            status_pt.add_row(["PORT    BGP Status:{0}".format(bgp.dto.get('status', None))])
            mainpt.add_row([str(pt)])
            mainpt.add_row([str(status_pt)])
        if printme:
            self.info('\n{0}\n'.format(mainpt))
        else:
            return mainpt

    def add_bgp_peer(self, router, port, local_as, peer_as, peer_addr):

        if isinstance(router, Router):
            pass
        if isinstance(router, basestring):
            pass
        raise NotImplementedError('Method not implemented yet')

    def _format_ad_routes(self, ad_routes):
        adrs = []
        if not isinstance(ad_routes, list):
            ad_routes = [ad_routes]
        for adr in ad_routes:
            adrs.append('{0}/{1}'.format(adr.get_nw_prefix(), adr.get_prefix_length()))
        return adrs

    def _update_euca_instances(self):
        instances = []
        reservations = self.eucaconnection.ec2_connection.get_all_instances(
            instance_ids=['verbose'])
        for res in reservations:
            if res.instances:
                instances.extend(res.instances)
        now = time.time()
        self._euca_instances = {'lastupdated': now, 'instances': instances}

    @property
    def euca_instances(self):
        """
        Attempt to cache instances locally for up to 5 seconds to speed up and prevent unnecessary
        instance look ups on system
        """
        if self._euca_instances:
            if time.time() - self._euca_instances.get('lastupdated', 0) < 5:
                return self._euca_instances['instances']
        self._update_euca_instances()
        return self._euca_instances['instances']

    def _get_instance_by_id(self, id):
        for x in xrange(0, 2):
            for instance in self.euca_instances:
                if instance.id == id:
                    return instance
            self._update_euca_instances()
        return None

    def _get_instance_by_private_ip(self, private_ip):
        for instance in self.euca_instances:
            if instance.private_ip_address == private_ip:
                return instance
        return None

    def _get_instance_by_public_ip(self, public_ip):
        for instance in self.euca_instances:
            if instance.ip_address == public_ip:
                return instance
        return None

    def show_bridges(self, bridges=None, indent=None, printme=True):
        if indent is None:
            indent = self.default_indent
        if bridges:
            if not isinstance(bridges, list):
                bridges = [bridges]
        else:
            bridges = self.mapi.get_bridges(query=None)
        printbuf = ""
        for bridge in bridges:
            buf = ""
            pt = PrettyTable(['BRIDGE NAME', 'ID', 'TENANT', 'Vx LAN PORT'])
            pt.add_row([bridge.get_name(), bridge.get_id(), bridge.get_tenant_id(),
                        bridge.get_vxlan_port()])
            title = self._header('BRIDGE:"{0}"'.format(bridge.get_name()))
            box = PrettyTable([title])
            box.align[title] = 'l'
            buf += self._bold("{0}BRIDGE SUMMARY:\n".format(indent), 4)
            buf += self._indent_table_buf(str(pt))
            buf += self._bold("{0}BRIDGE PORTS:\n".format(indent), 4)
            buf += self._indent_table_buf(self.show_ports(bridge.get_ports(), printme=False))
            buf += self._bold("{0}BRIDGE ARP TABLE:\n".format(indent), 4)
            buf += self._indent_table_buf(self.show_bridge_arp_table(bridge=bridge, printme=False))
            buf += self._bold("{0}BRIDGE DHCP SUBNETS:\n".format(indent))
            buf += self._indent_table_buf(self.show_bridge_dhcp_subnets(bridge, printme=False))
            buf += self._bold("{0}BRIDGE MAC TABLE:\n".format(indent))
            buf += self._indent_table_buf(self.show_bridge_mac_table(bridge=bridge, printme=False))
            box.add_row([buf])
            printbuf += str(box) + "\n"
        if printme:
            self.info('\n{0}\n'.format(printbuf))
        else:
            return printbuf

    def show_bridge_dhcp_subnets(self, bridge, printme=True):
        pt = PrettyTable(['SUBNET', 'SERVER ADDR', 'DefaultGW', 'DNS SERVERS', 'STATE'])
        for subnet in bridge.get_dhcp_subnets():
            pt.add_row(["{0}/{1}".format(subnet.get_subnet_prefix(), subnet.get_subnet_length()),
                        subnet.get_server_addr(),
                        subnet.get_default_gateway(),
                        ",".join(str(dns) for dns in subnet.get_dns_server_addrs()),
                        subnet.dto.get('enabled')])
        if printme:
            self.info('\n{0}\n'.format(pt))
        else:
            return pt

    def get_bridge_arp_table(self, bridge):
        table = bridge.get_children(bridge.dto['arpTable'],
                                    query=None,
                                    headers={"Accept": ""},
                                    clazz=ArpTable)
        return table

    def get_bridge_mac_table(self, bridge):
        table = bridge.get_children(bridge.dto['macTable'],
                                    query=None,
                                    headers={"Accept": ""},
                                    clazz=MacTable)
        return table

    def show_bridge_mac_table(self, bridge, printme=True):
        pt = PrettyTable(['BRIDGE ID', 'MAC ADDR', 'PORT ID', 'VLAN ID'])
        mac_table = self.get_bridge_mac_table(bridge)
        for entry in mac_table:
            assert isinstance(entry, MacTable)
            pt.add_row([entry.get_bridge_id(), entry.get_macaddr(), entry.get_port_id(),
                        entry.get_vlan_id()])
        if printme:
            self.info('\n{0}\n'.format(pt))
        else:
            return pt

    def show_bridge_arp_table(self, bridge, printme=True):
        pt = PrettyTable(['IP', 'MAC', 'MAC ADDR', 'VM ID', 'NC', 'LEARNED PORT'])
        table = self.get_bridge_arp_table(bridge)
        mac_table = self.get_bridge_mac_table(bridge)
        for entry in table:
            instance_id = None
            vm_host = None
            entry_ip = entry.get_ip()
            port = "NOT LEARNED"
            for mac in mac_table:
                if mac.get_macaddr() == entry.get_mac():
                    port = mac.get_port_id()
            if self.eucaconnection:
                try:
                    euca_instance = self._get_instance_by_private_ip(private_ip=entry_ip)
                    if euca_instance:
                        instance_id = self._bold(euca_instance.id)
                        vm_host = euca_instance.tags.get('euca:node', None)
                except:
                    raise
            pt.add_row([entry_ip, entry.get_mac(), entry.get_macaddr(), instance_id,
                        vm_host, port])
        if printme:
            self.info('\n{0}\n'.format(pt))
        else:
            return pt

    def get_bridge_port_for_instance_learned(self, instance):
        instance = self._get_instance(instance)
        bridge = self.get_bridge_for_instance(instance)
        arp_table = self.get_bridge_arp_table(bridge)
        mac_table = self.get_bridge_mac_table(bridge)
        arp_entry = None
        for a_entry in arp_table:
            if a_entry.get_ip() == instance.private_ip_address:
                arp_entry = a_entry
                break
        if arp_entry:
            for m_entry in mac_table:
                if m_entry.get_macaddr() == arp_entry.get_mac():
                    portid = m_entry.get_port_id()
                    return self.mapi.get_port(portid)
            self.info('ARP entry for instance found, but mac has not been learned on a port yet, '
                      'try pinging it?   ')
        return None

    def get_bridge_port_for_instance_by_port_name(self, instance):
        instance = self._get_instance(instance)
        host = self.get_host_for_instance(instance)
        assert isinstance(host, Host)
        for port in host.get_ports():
            iname = port.get_interface_name()
            lookfor_name = 'vn_' + str(instance.id)
            if re.search(lookfor_name, iname):
                return self.mapi.get_port(port.get_port_id())
        return None

    def show_bridge_port_for_instance(self, instance, showchains=True, indent=None, printme=True):
        instance = self._get_instance(instance)
        if indent is None:
            indent = self.default_indent
        bridge = self.get_bridge_for_instance(instance)
        learned = "(LEARNED)"
        port = self.get_bridge_port_for_instance_learned(instance)
        if not port:
            learned = "(NOT LEARNED)"
            port = self.get_bridge_port_for_instance_by_port_name(instance)
        title = self._bold('BRIDGE PORT FOR INSTANCE:{0}, (BRIDGE:{1}), {2}'
                           .format(instance.id, bridge.get_name() or bridge.get_id(), learned), 94)
        pt = PrettyTable([title])
        pt.align[title] = 'l'
        buf = ""
        if port:
            buf += str(self.show_port_summary(port, showchains=showchains, printme=False))
        pt.add_row([buf])
        if printme:
            self.info('\n{0}\n'.format(pt))
        else:
            return pt

    def get_chain_by_name(self, name):
        chains = self.mapi.get_chains(query=None)
        for chain in chains:
            if str(chain.get_name()).strip() == str(name):
                return chain
        return None

    def get_chain_by_id(self, id):
        chains = self.mapi.get_chains(query=None)
        for chain in chains:
            if str(chain.get_id()).strip() == str(id):
                return chain
        return None

    def show_chain(self, chain, printme=True):
        if chain and isinstance(chain, unicode) or isinstance(chain, str):
            if re.match('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$', chain):
                chain = self.get_chain_by_id(chain)
            else:
                chain = self.get_chain_by_name(chain)
            raise ValueError('Chain:"{0}" not found in show_chain'.format(chain))
        if not isinstance(chain, Chain):
            raise ValueError("Unsupported type passed to show_chain, chain:'{0}:{1}'"
                             .format(chain, type(chain)))
        title = 'CHAIN NAME:{0}, ID:{1} TENANT ID:{2}'.format(chain.dto.get('name', "NA"),
                                                              self._bold(chain.get_id(),
                                                                         self._CHAIN_JUMP),
                                                              chain.dto.get('tenantId', ""))
        pt = PrettyTable([title])
        pt.align[title] = 'l'
        rules = chain.get_rules()
        if not rules:
            pt.add_row(['NO RULES'])
        else:
            rulesbuf = str(self.show_rules(rules=chain.get_rules(), jump=True, printme=False))
            pt.add_row([rulesbuf])
        if printme:
            self.info('\n{0}\n'.format(pt))
        else:
            return pt

    def show_chains_for_instance_security_groups(self, instance, printme=True):
        instance = self._get_instance(instance)
        if not instance.groups:
            self.info('Instance.groups is empty')
        mainbuf = self._bold("\nSECURITY GROUP/MIDO CHAIN RULE MAPPING for INSTANCE: '{0}'"
                             .format(instance.id))
        for group in instance.groups:
            buf = ""
            title = 'MIDO CHAIN RULES FOR EUCA SECURITY GROUP:{0} ({1})'.format(group.id,
                                                                                group.name)
            pt = PrettyTable([title])
            pt.align[title] = 'l'
            buf += "\n" + str(self.show_security_group(group, printme=False))
            buf += "\n" + str(self.show_chain_for_security_group(group, printme=False))
            pt.add_row([buf])
            mainbuf += "\n" + str(pt)
        if printme:
            self.info(mainbuf)
        else:
            return mainbuf

    def get_chain_for_security_group(self, group):
        # sg_ingress_sg-012aee24
        group_id = None
        if isinstance(group, SecurityGroup) or isinstance(group, BotoGroup):
            group_id = str(group.id)
        elif group:
            if isinstance(group, str) or isinstance(group, unicode):
                if re.match('^sg-\w{8}$', group):
                    group = self.get_security_group(id=group)
                    self._errmsg('Could not find security group:"{0}" on cloud? Trying to lookup'
                                 'midonet chain anyways...'.format(group))
                    group_id = str(group)
                else:
                    group = self.get_security_group(name=group)
                    if not group:
                        raise ValueError('Group not found on system and not could not perform'
                                         'a chain lookup because group was not provided in '
                                         'id format, ie:"sg-XXXXXXXX", group:"{0}"'.format(group))
        if not group_id:
            raise RuntimeError('Group id is none, lookup failed for provided group arg:"{0}"'
                               .format(group))
        chain_name = "sg_ingress_" + str(group_id)
        chain = self.get_chain_by_name(name=chain_name)
        if not chain:
            self._errmsg('Chain lookup failed, this could be expected if security group is extant '
                         'and no running are referencing it')
        else:
            return chain

    def show_chain_for_security_group(self, group, printme=True):
        chain = self.get_chain_for_security_group(group)
        return self.show_chain(chain, printme=printme)

    def does_chain_allow(self, chain, src_addr, protocol, port):
        if not isinstance(chain, Chain):
            raise ValueError('does_chain_allow passed non Chain type:"{0}:{1}"'
                             .format(chain, type(chain)))
        if not src_addr or not protocol or not port:
            raise ValueError('Missing or empty arg not provided; src_addr:"{0}", protocol:"{1}", '
                             'port:"{2}"'.format(src_addr, protocol, port))
        protocol = str(protocol).upper().strip()
        port = int(port)
        for rule in chain.get_rules():
            src_ip = str(rule.get_nw_src_address() or '0.0.0.0')
            src_mask = str(rule.get_nw_src_length() or 0)
            rule_cidr = src_ip + "/" + src_mask
            rule_protocol = self._get_protocol_name_by_number(rule.get_nw_proto())
            port_dict = rule.get_tp_dst()
            start_port = port_dict.get('start')
            end_port = port_dict.get('end')
            if protocol == str(rule_protocol).upper().strip():
                if port >= start_port and port <= end_port:
                    if rule_cidr == "0.0.0.0/0" or is_address_in_network(src_addr, rule_cidr):
                        self.info('Found rule which allows src_addr:"{0}", protocol:"{1}", '
                                  'port:"{2}"'.format(src_addr, protocol, port))
                        self.show_rules(rules=[rule])
                        return True
        self.info('Chain does not allow: src_addr:"{0}", protocol:"{1}", port:"{2}"'
                  .format(src_addr, protocol, port))
        return False

    def get_unsynced_rules_for_security_group(self, group, show_rules=True):
        chain = self.get_chain_for_security_group(group)
        unsynced_rules = []
        for rule in group.rules:
            if not self.get_security_group_rule_mapping_from_backend(group, rule):
                unsynced_rules.append(rule)
        self.info('{0} unsynced rules out of {1} total rules found for group:"{2}"'
                  .format(len(unsynced_rules), len(group.rules), group.name))
        if unsynced_rules and show_rules:
            title = markup('The following rules for group:"{0}" were not found) on '
                           'backend'.format(group.name), [1, 91, 7])
            main_pt = PrettyTable([title])
            pt = PrettyTable(['cidr_ip', 'src_grp_name', 'src_grp_id', 'protocol', 'port_range'])
            for rule in unsynced_rules:
                for grant in rule.grants:
                    pt.add_row([grant.cidr_ip, grant.name, grant.group_id, rule.ip_protocol,
                                "{0}:{1}".format(rule.from_port, rule.to_port)])
            main_pt.add_row([str(pt)])
            self.info("\n" + str(main_pt) + "\n")
        return unsynced_rules

    def get_unsynced_rules_for_instance(self, instance, show_rules=True):
        unsynced_rules = []
        for group in instance.groups:
            group = self.get_security_group(id=group.id)
            unsynced_rules.extend(self.get_unsynced_rules_for_security_group(
                group, show_rules=show_rules))
        self.info('Number of unsynced rules found for instance ({0}):{1}'
                  .format(instance.id, len(unsynced_rules)))
        return unsynced_rules

    def get_security_group_rule_mapping_from_backend(self, group, security_group_rule):
        """
        Attempts to find the provided security group rule within midonent.
        :param group: A Euca security group id, or boto security group object
        :param security_group_rule: A boto IPPermissions obj (rule).
        :returns the midonet rule(s) which support the security group rule provided
        """
        ret_rules = []
        assert isinstance(security_group_rule, IPPermissions), \
            'security_group_rule arg must be of type boto.IPPermissions, got:"{0}:{1}' \
            .format(security_group_rule, type(security_group_rule))
        chain = self.get_chain_for_security_group(group)
        ip_grants = copy.copy(security_group_rule.grants)
        protocol = (security_group_rule.ip_protocol and
                    str(security_group_rule.ip_protocol).upper() or None)
        from_port = security_group_rule.from_port
        to_port = security_group_rule.to_port
        if from_port is not None:
            from_port = int(from_port)
        if to_port is not None:
            to_port = int(to_port)
        if from_port == -1:
            from_port = None
        if to_port == -1:
            to_port = None
        for grant in security_group_rule.grants:
            self.info(self._bold('Looking for chain rule against grant: cidr_ip:"{0}", '
                                 'srg_grp:"{1}", proto:"{2}", start_port:"{3}", end_port:"{4}"'
                                 .format(grant.cidr_ip, grant.group_id,
                                         security_group_rule.ip_protocol,
                                         security_group_rule.from_port,
                                         security_group_rule.to_port)))
            for rule in chain.get_rules():
                match = False
                protocol_number = rule.get_nw_proto()
                r_protocol = None
                if protocol_number is not None:
                    r_protocol = str(self._get_protocol_name_by_number(protocol_number)).upper()
                self.info('checking protocol:"{0}" vs rule_proto:"{1}"'.format(protocol,
                                                                               r_protocol))
                if not (protocol == r_protocol):
                    continue
                port_dict = rule.get_tp_dst() or {}
                start_port = port_dict.get('start')
                end_port = port_dict.get('end')
                self.info('Protocol matched, checking fport:{0} vs sport:{1}, and tport:{2}'
                          ' vs eport:{3}'.format(from_port, start_port, to_port, end_port))
                if not (from_port == start_port and to_port == end_port):
                    continue
                self.info('Rules port and protocols match up, now ip/src grp comparison...')
                src_ip = str(rule.get_nw_src_address() or '0.0.0.0')
                src_mask = str(rule.get_nw_src_length() or 0)
                rule_cidr = src_ip + "/" + src_mask
                ip_addr_grp_id = rule.get_ip_addr_group_src()
                ip_addr_grp_name = ""
                self.info('This rule has ipaddr group:"{0}"'.format(ip_addr_grp_id))
                if ip_addr_grp_id:
                    ip_addr_grp = self.mapi.get_ip_addr_group(ip_addr_grp_id)
                    if ip_addr_grp:
                        ip_addr_grp_name = str(ip_addr_grp.get_name())
                        self.info('This rule has ipaddr group name:"{0}"'
                                  .format(ip_addr_grp_name))
                self.info('checking grant.cidr_ip:"{0}" vs rule_cidr:"{1}"'
                          .format(grant.cidr_ip, rule_cidr))
                if grant.cidr_ip and (str(grant.cidr_ip) == rule_cidr):
                    match = True
                elif grant.group_id and str(grant.group_id) in ip_addr_grp_name:
                    match = True
                if match:
                    self.info('Found rule for cidr_ip:"{0}", srg_grp:"{1}", proto:"{2}", '
                              'start_port:"{3}", end_port:"{4}"'
                              .format(grant.cidr_ip, grant.group_id, protocol, from_port, to_port))
                    if rule not in ret_rules:
                        ret_rules.append(rule)
                    if grant in ip_grants:
                        ip_grants.remove(grant)
                        break
        self.info('Found "{0}" rules for; Group:"{1}", ip_grants:"{2}", proto:"{3}", '
                  'start_port:"{4}", end_port:"{5}"'
                  .format(len(ret_rules), group, security_group_rule.grants, protocol, from_port,
                          to_port))
        if ret_rules:
            self.show_rules(rules=ret_rules)
        return ret_rules

    def do_instance_rules_allow(self, instance, src_addr, protocol, port):
        for group in instance.groups:
            chain = self.get_chain_for_security_group(group)
            self.info('Checking midonet chain:"{0}" for instance:"{1}", security group "{2}"'
                      .format(chain.get_name(), instance.id, group.name))
            if self.does_chain_allow(chain=chain, src_addr=src_addr, protocol=protocol, port=port):
                return True
        return False

    def show_rules(self, rules, jump=False, printme=True):
        '''
            midonet> chain ec8b6a76-63b0-4952-89de-33b62da492e7 list rule
            rule rule0 dst !172.31.0.2 proto 0 tos 0 ip-address-group-src ip-address-group1
            fragment-policy any pos 1 type snat action continue target 10.116.169.162

            dst $nwDstAddress/$nwDstLength  proto $nwProto tos $nwTos
            ip-address-group-src $ipAddrGroupSrc fragment-policy $fragmentPolicy pos $position
            type $type action $natFlowAction target $natTargets
        '''
        def invert(inv_meth):
            if inv_meth():
                return "!"
            else:
                return  ""

        if not isinstance(rules, list):
            rules = [rules]
        buf = ""
        pt = None
        for rule in rules:
            if pt is None:
                chain_id = rule.get_chain_id()
                # title = "RULE(S) FOR CHAIN: {1}".format(rules.index(rule),chain_id)

                title = "RULES FOR CHAIN:{0}".format("..{0}{1}".format(chain_id[-5:-1],
                                                                       chain_id[-1]))
                title_width = len(title)
                pt = PrettyTable([title, 'SRC', 'DST', 'PROTO', 'DPORTS', 'TOS',
                                  'GRP ADDRS', 'FRAG POL',
                                  'POS', 'TYPE', 'ACTION', 'TARGET'])
                pt.padding_width = 0
                pt.max_width[title] = title_width
                pt.align[title] = 'l'
                pt.max_width['TARGET'] = self._ADDR_SPACING
                pt.align['TARGET'] = 'l'
                pt.max_width['GRP ADDRS'] = self._ADDR_SPACING
                pt.align['GRP ADDRS'] = 'l'
                pt.hrules = 1
            jump_chain = None
            action = rule.dto.get('flowAction', "")
            targets = []
            nattargets = rule.dto.get('natTargets') or []
            ports = None
            tpdst = rule.dto.get('tpDst', None)
            if tpdst:
                ports = "{0}:{1}".format(tpdst.get('start', ""), tpdst.get('end', ""))
            rule_type = self._bold(rule.get_type())
            for nattarget in nattargets:
                targets.append(nattarget.get('addressFrom'))
            targetstring = self._bold(",".join(targets))
            if rule.get_type().upper() == 'JUMP':
                jump_chain_id = rule.get_jump_chain_id()
                jump_chain = self.mapi.get_chain(jump_chain_id)
                rule_type = self._bold(rule.get_type(), self._CHAIN_JUMP)
                action = self._bold('to chain', self._CHAIN_JUMP)
                targetstring = jump_chain_id
            ip_addr_group = rule.get_ip_addr_group_src()
            if ip_addr_group:
                ip_addr_group = self.show_ip_addr_group_addrs(ipgroup=ip_addr_group, printme=False)
            pt.add_row(['{0} {1}'.format(self._bold("RULE#:" +
                                                    str(rules.index(rule) + 1)).ljust(title_width),
                                         rule.get_id()),
                        "{0}{1}/{2}".format(invert(rule.is_inv_nw_src), rule.get_nw_src_address(),
                                          rule.get_nw_src_length()),
                        "{0}{1}/{2}".format(invert(rule.is_inv_nw_dst), rule.get_nw_dst_address(),
                                          rule.get_nw_dst_length()),
                        "{0}{1}".format(invert(rule.is_inv_nw_proto),
                                        self._get_protocol_name_by_number(rule.get_nw_proto())),
                        "{0}{1}".format(invert(rule.is_inv_tp_dst), ports),
                        "{0}{1}".format(invert(rule.is_inv_nw_tos), rule.get_nw_tos()),
                        "{0}{1}".format(invert(rule.is_inv_ip_addr_group_src), ip_addr_group),
                        rule.get_fragment_policy(),
                        rule.get_position(),
                        rule_type,
                        action,
                        targetstring])
            if jump_chain and jump:
                buf += str(pt) + "\n"
                pt = None
                # buf += "|\n" + "+->\n"
                # buf += str(self.show_chain(jump_chain, printme=False)) + "\n"
                buf += self._link_table_buf(self.show_chain(jump_chain, printme=False))
        buf += str(pt)
        if printme:
            self.info('\n{0}\n'.format(buf))
        else:
            return buf

    def show_router_for_instance(self, instance, printme=True):
        instance = self._get_instance(instance)
        ret_buf = self._highlight_buf_for_instance(
            buf=self.show_router_summary(router=self.get_router_for_instance(instance=instance),
                                         printme=False),
            instance=instance)
        if printme:
            self.info('\n{0}\n'.format(ret_buf))
            return None
        else:
            return ret_buf

    def show_bridge_for_instance(self, instance, printme=True):
        instance = self._get_instance(instance)
        ret_buf = self._highlight_buf_for_instance(
            buf=self.show_bridges(bridges=self.get_bridge_for_instance(instance=instance),
                                  printme=False),
            instance=instance)
        if printme:
            self.info('\n{0}\n'.format(ret_buf))
            return None
        else:
            return ret_buf

    def show_instance_network_summary(self, instance, printme=True):
        instance = self._get_instance(instance)
        self.info('Gathering network info... (this may take a few seconds)')
        title = ("NETWORK SUMMARY FOR INSTANCE:{0}, (PRIVIP:{1}, PUBIP:{2})"
                 .format(instance.id, instance.private_ip_address, instance.ip_address))
        pt = PrettyTable([title])
        pt.align[title] = 'l'
        pt.border = 0
        pt.padding_width = 0
        buf = str(self.show_router_for_instance(instance=instance, printme=False))
        buf += str(self.show_bridge_for_instance(instance=instance, printme=False))
        buf += str(self.show_bridge_port_for_instance(instance=instance, printme=False))
        buf += str(self.show_host_for_instance(instance=instance, printme=False))
        buf += "\n"
        eucatitle = self._bold('"EUCALYPTUS CLOUD" INSTANCE INFO ({0}):'.format(instance.id), 94)
        ept = PrettyTable([eucatitle])
        ept.align[eucatitle] = 'l'
        secpt = self.show_security_groups_for_instance(instance, printme=False)
        secpt.border = 0
        secpt.padding_width = 0
        ebuf = "\n{0}\n".format(secpt)
        # ebuf = "\n" + str(self.eucaconnection.show_instance(instance, printme=False)) + "\n"
        ept.add_row([ebuf])
        buf += str(ept)
        pt.add_row([buf])
        if printme:
            self.info('\n{0}\n'.format(pt))
        else:
            return pt


    def show_ip_addr_group_addrs(self, ipgroup, printme=True):
        if not isinstance(ipgroup, IpAddrGroup):
            ipgroup = self.mapi.get_ip_addr_group(ipgroup)
        if not ipgroup:
            raise ValueError('ipgroup not found or populated for show_ip_addr_group_addrs')
        addrs = [("({0})".format(ipgroup.get_name())).ljust(self._ADDR_SPACING)]
        grpaddrs = ipgroup.get_addrs()
        for ga in grpaddrs:
            addr = ga.get_addr()
            if addr:
                addrs.append(str(" - {0}".format(addr)).ljust(self._ADDR_SPACING))
        ret_buf = " ".join(addrs)
        if printme:
            self.info('\n{0}\n'.format(ret_buf))
        else:
            return ret_buf

    def show_hosts_summary(self, hosts=None, printme=True):
        if hosts and not isinstance(hosts, list):
            assert isinstance(hosts, Host)
            hosts = [hosts]
        if hosts is None:
            hosts = self.mapi.get_hosts(query=None)
        host_name_col = 'HOST NAME'
        pt = PrettyTable(["HOST ID", host_name_col, "ALIVE", "HOST IP(S)", 'TUN ZONE'])
        for host in sorted(hosts, key=lambda host: host.get_name()):
            ip_addrs = 'not resolved'
            try:
                name, aliaslist, addresslist = socket.gethostbyaddr(host.get_name())
                ip_addrs = ", ".join(addresslist)
            except:
                pass
            tz = self.get_tunnel_zone_for_host(host)
            if tz:
                tz = tz.get_name()
            pt.add_row([host.get_id(), host.get_name(), host.dto.get('alive'), ip_addrs, tz])
        if printme:
            self.info('\n{0}\n'.format(pt))
        else:
            return pt

    def get_tunnel_zone_for_host(self, host):
        tzs = self.get_tunnel_zones()
        for tz in tzs:
            for thosts in tz.get_hosts():
                if thosts.get_host_id() == host.get_id():
                    return tz
        return None


    def show_hosts(self, hosts=None, printme=True):
        if hosts and not isinstance(hosts, list):
            assert isinstance(hosts, Host)
            hosts = [hosts]
        if hosts is None:
            hosts = self.mapi.get_hosts(query=None)
        buf = "\n"
        for host in sorted(hosts, key=lambda host: host.get_name()):
            title = self._bold("HOST:{0} ({1})".format(host.get_name(), host.get_id()), 94)
            pt = PrettyTable([title])
            pt.align[title] = "l"
            hostbuf = self._bold("HOST SUMMARY:\n", 4)
            hostbuf += self._indent_table_buf(str(self.show_hosts_summary(hosts=host,
                                                                          printme=False)))
            hostbuf += self._bold("HOST PORTS:\n", 4)
            hostbuf += self._indent_table_buf(str(self.show_host_ports(host, printme=False)))
            hostbuf += self._bold("HOST INTERFACES:\n", 4)
            hostbuf += self._indent_table_buf(str(self.show_host_interfaces(host, printme=False)))
            pt.add_row([hostbuf])
            buf += "\n" + str(pt) + "\n"
        if printme:
            self.info('{0}'.format(buf))
        else:
            return buf

    def get_ip_for_host(self, host):
        if isinstance(host, Host):
            host = host.get_name()
        name, aliaslist, addresslist = socket.gethostbyaddr(host)
        if addresslist:
            return addresslist[0]
        return None

    def restart_backend(self, hosts=None):
        """
        Generic reset method not specific to a midonet backend, for tests to call...
        """
        return self.reset_midolman_service_on_hosts(hosts=hosts)

    def reset_midolman_service_on_hosts(self, hosts=None, username=None, password=None,
                                        keypath=None):
        if hosts and not isinstance(hosts, list):
            assert isinstance(hosts, Host)
            hosts = [hosts]
        result = {}
        failed = False

        if hosts is None:
            try:
                hosts = self.get_midolman_hosts_from_zk()
            except Exception as E:
                self.log.error('Failed to fetch hosts from zookeeper, err: {0}'.format(E))
                api_hosts = self.mapi.get_hosts(query=None) or []
                hosts = []
                for host in api_hosts:
                    hosts.append(host.get_name())
        if not hosts:
            raise ValueError('No hosts provided or found from zookeeper or mido api?')
        self.info('Attempting to stop all hosts first...')
        self.info('Restarting hosts: {0}'.format(",".join(hosts)))
        for status in ['stop', 'start']:
            for host in hosts:
                ip = "None"
                try:
                    success = True
                    error = None
                    ip = self.get_ip_for_host(host)
                    ssh = self.get_host_ssh(host, username=username, password=password,
                                            keypath=keypath)
                    try:
                        machine = Machine(ssh.host, sshconnection=ssh)
                        if (machine.distro[0] in ['rhel', 'centos']) and \
                            (int(machine.distro_ver[0]) > 6):
                            machine.sys('systemctl restart midolman')
                            continue
                    except Exception as SE:
                        self.log.warn('systemctl failed on host:"{0}", err:{1}\n'
                                      'Trying init.d now...'.format(host, SE))
                    self.info("Attempting to {0} host:{1} ({2})".format(status,
                                                                        host, ip))
                    ssh.sys('service midolman {0}'.format(status), code=0)
                    time.sleep(1)
                except Exception as SE:
                    self.log.warning('\n{0}\n'.format(get_traceback()))
                    failed = True
                    success = False
                    error = str(SE)
                    self.log.warning('{0}({1}), midolman service failed to:{2}. Err:"{3}"'
                                     .format(host, ip, status, str(SE)))
                result[host] = {'action': status, 'success':success, 'error': error}

        if failed:
            errors = 'Errors while reseting midolman on hosts:\n'
            for host, info in result.iteritems():
                if info.get('success') is False:
                    errors += "host:{0}, action:{1}, success:{1}, error:{3}\n"\
                        .format(host, info.get('action'), info.get('success'), info.get('error'))
            self.log.warning(errors)
        else:
            self.info('Done restarting midolman on hosts')
        return result

    def get_host_ssh(self, host, username=None, password=None, keypath=None, timeout=10):
        if isinstance(host, Host):
            host = host.get_name()
            if not host:
                raise RuntimeError('host.get_name() did not return a name?')
        if not isinstance(host, basestring):
            raise ValueError('Unkown type for host: "{0}/{1}"'.format(host, type(host)))
        ip = self.get_ip_for_host(host)
        for host, info in self._host_connections.iteritems():
            if host == host or (ip and info.get('ip') == ip):
                return info.get('ssh')
        try:
            euca_host = self.eucaconnection.get_host_by_hostname(ip)
        except Exception as E:
            self.log.warning('Error fetching host from eucahost: {0}'.format(E))
        if not euca_host:
            username = username or self.eucaconnection.clc_machine.ssh.username
            password = password or self.eucaconnection.clc_machine.ssh.password
            keypath = keypath or self.eucaconnection.clc_machine.ssh.keypath
            ssh = sshconnection.SshConnection(host=ip, username=username,
                                              password=password, keypath=keypath, timeout=timeout,
                                              banner_timeout=10)
        else:
            ssh = euca_host.ssh
        self._host_connections[host] = {'ip': ip, 'ssh': ssh}
        return ssh

    def show_host_ports(self, host, printme=True):
        '''
        Fetches the 'HostInterfacePort's from a specific host and presents them in a formatted
        table
        '''
        assert isinstance(host, Host)
        ports = host.get_ports()
        porttable = PrettyTable(["HOST PORT NAME", "HOST PORT ID"])
        for port in ports:
            assert isinstance(port, HostInterfacePort)
            porttable.add_row([port.get_interface_name(), port.get_port_id()])
        if printme:
            self.info('\n{0}\n'.format(porttable))
        else:
            return porttable

    def show_host_interfaces(self, host, printme=True):
        '''
        Fetches the 'HostInterface's from a specific host and presents them in a formatted
        table
        '''
        assert isinstance(host, Host), 'host type ({0}) is not of midonet Host type' \
            .format(type(host))
        interfaces = host.get_interfaces()
        pt = PrettyTable(['NAME', 'TYPE', 'MAC', 'STATUS', 'MTU', 'ENDPOINT', 'ADDRESSES'])
        for hi in interfaces:
            assert isinstance(hi, HostInterface), "host interface type({0}) is not of midonet " \
                                                  "Host Interface type ".format(type(hi))
            pt.add_row([hi.get_name(), hi.get_type(), hi.get_mac(), hi.get_status(), hi.get_mtu(),
                        hi.get_endpoint(), ", ".join(hi.get_addresses() or [])])
        if printme:
            self.info('\n{0}\n'.format(pt))
        else:
            return pt

    def show_host_for_instance(self, instance, printme=True):
        instance = self._get_instance(instance)
        host = self.get_host_for_instance(instance)
        return self.show_hosts(hosts=host, printme=printme)

    def get_host_for_instance(self, instance):
        instance = self._get_instance(instance)
        instance.update()
        node = self.eucaconnection.get_hosts_for_node_controllers(instanceid=instance.id)
        if not node:
            if instance.state != 'running':
                self.log.error('Node, not found. Try again when instance is running, '
                                  'current state:{0}'.format(instance.state))
            raise ValueError('Node for instance:"{0}" not found?'.format(instance.id))
        node = node[0]
        host = self.get_host_by_hostname(node.hostname)
        if not host:
            raise ValueError('Mido Host for instance:"{0}" not found?'.format(instance.id))
        return host

    def get_host_by_hostname(self, name):
        """
        Fetch a specific host by either ip address or hostname.
        Attempts to match to resolve and then match to the host's name attribute
        returns the host object if found
        """
        name, aliaslist, addresslist = socket.gethostbyaddr(name)
        self.info('looking up host with name:{0}'.format(name))
        for host in self.mapi.get_hosts():
            if host.get_name() == name:
                return host
        return None

    def get_instance_learned_port_by_ping(self, instance):
        # Port may not be currently active/learned on the bridge,
        # try to ping the private interface...
        instance = self._get_instance(instance)
        port = self.get_bridge_port_for_instance_learned(instance)
        if not port:
            try:
                self.info(self._bold("MAC IS NOT LEARNED ON A BRIDGE PORT AT THIS TIME !?!", 91))
                self.info(self._bold("Trying to ping the instance private addr('{0}') now...?)"
                                     .format(instance.private_ip_address), 91))
                self.ping_instance_private_ip_from_euca_internal(instance)
            except RuntimeError:
                pass
        port = self.get_bridge_port_for_instance_learned(instance)
        return port

    def get_tunnel_zones(self, name=None, id=None):
        if id:
            return self.mapi.get_tunnel_zone(id)
        elif name:
            tzones = self.mapi.get_tunnel_zones()
            for tz in tzones:
                if str(tz.get_name()) == str(name):
                    return tz
        else:
            return self.mapi.get_tunnel_zones()
        return None


    def show_tunnel_zones(self, tzones=None, highlight_ip=None, printme=True):
        ip = highlight_ip
        tzones = tzones or self.get_tunnel_zones()
        if not isinstance(tzones, list):
            tzones = [tzones]
        main_pt = PrettyTable(['TUNNEL ZONES'])
        main_pt.header = False
        main_pt.border = False
        main_pt.align = 'l'
        for tz in tzones:
            title = markup("Name:{0}, {1}, type:{2}".format(tz.get_name(),
                                                            tz.get_id(),
                                                            tz.get_type()), [1, 94])
            mediapt = ("HostListMediaType:{0}, HostMediaType:{1}"
                       .format(tz.__dict__.get('tunnel_zone_host_list_media_type'),
                               tz.__dict__.get('tunnel_zone_host_media_type')))
            tzpt = PrettyTable([title])
            tzpt.align = 'l'
            tzpt.add_row([mediapt])
            hostpt = PrettyTable(['HOST IP', 'HOST ID'])
            hostpt.align = 'l'
            for host in tz.get_hosts():
                host_ip = host.get_ip_address()
                if ip and host_ip == ip:
                    host_ip = markup(host_ip, 102)
                hostpt.add_row([host_ip, host.get_host_id()])
            tzpt.add_row([str(hostpt)])
            main_pt.add_row([tzpt])
        if printme:
            self.info("\n{0}\n".format(main_pt))
        else:
            return main_pt

    def get_security_group(self, id=None, name=None):
        """
         Adding this as both a convienence to the user to separate euare groups
         from security groups
        """
        # To allow easy updating of a group (since group.update() is not implemented at this time),
        # handle SecurityGroup arg type for either kwargs...
        names = ['verbose']
        ids = None
        if isinstance(id, SecurityGroup) or isinstance(id, BotoGroup):
            id = id.id
        if isinstance(name, SecurityGroup) or isinstance(name, BotoGroup):
            name = name.name
        if not id and not name:
            raise Exception('get_security_group needs either a name or an id')
        if id:
            ids = [id]
        if name:
            names.append(name)
        groups = self.eucaconnection.ec2_connection.get_all_security_groups(groupnames=names,
                                                                            group_ids=ids)
        for group in groups:
            if not id or (id and group.id == id):
                if not name or (name and group.name == name):
                    self.info('Found matching security group for name:' + str(name) +
                              ' and id:' + str(id))
                    return group
        self.info('No matching security group found for name:' + str(name) +
                  ' and id:' + str(id))
        return None

    def show_security_group(self, group, printme=True):
        try:
            from prettytable import PrettyTable, ALL
        except ImportError as IE:
            self.info('No pretty table import failed:' + str(IE))
            return
        group = self.get_security_group(id=group.id)
        if not group:
            raise ValueError('Show sec group failed. Could not fetch group:' + str(group))
        title = markup("Security Group: {0}/{1}, VPC: {2}"
                       .format(group.name, group.id, group.vpc_id))
        maintable = PrettyTable([title])
        maintable.padding_width = 0
        maintable.align["title"] = 'l'
        table = PrettyTable(["CIDR_IP", "SRC_GRP_NAME",
                             "SRC_GRP_ID", "OWNER_ID", "PORT",
                             "END_PORT", "PROTO"])
        table.vrules = 2
        table.padding_width = 0
        for rule in group.rules:
            port = rule.from_port
            end_port = rule.to_port
            proto = rule.ip_protocol
            for grant in rule.grants:
                table.add_row([grant.cidr_ip, grant.name,
                               grant.group_id, grant.owner_id, port,
                               end_port, proto])
        table.hrules = ALL
        maintable.add_row([str(table)])
        if printme:
            self.info("\n{0}".format(str(maintable)))
        else:
            return maintable

    def show_security_groups_for_instance(self, instance, printmethod=None, printme=True):
        instance = self._get_instance(instance)
        buf = ""
        title = markup("EUCA SECURITY GROUPS FOR INSTANCE:{0}".format(instance.id))
        pt = PrettyTable([title])
        pt.align['title'] = 'l'
        for group in instance.groups:
            buf += str(self.show_security_group(group=group, printme=False))
        pt.add_row([buf])
        if printme:
            printmethod = printmethod or self.debug
            printmethod('\n{0}\n'.format(pt))
        else:
            return pt

    def show_instance_meta_data_artifacts(self, instance, printmethod=None, printme=True):
        self.log.info('Not implemented yet')


    def get_euca_subnet_metadata_addr(self, subnet):
        if isinstance(subnet, basestring):
            subnet = self.eucaconnection.ec2_connection.get_all_subnets([subnet, 'verbose'])[0]
        cidr = subnet.cidr_block
        network, netmask = cidr.split('/')
        octets = network.split('.')
        octets[-1] = int(octets[-1]) + 2
        metaip = ".".join(str(x) for x in octets)
        return metaip

    def get_instance_bridge_port_metadata_nat_rule(self, instance):
        instance = self._get_instance(instance)
        metaip = self.get_euca_subnet_metadata_addr(instance.subnet_id)
        port = self.get_bridge_port_for_instance_by_port_name(instance)
        chain = self.mapi.get_chain(port.get_outbound_filter_id())
        rules = chain.get_rules()
        for rule in rules:
            if rule.get_nw_src_address() == metaip:
                for nat in rule.dto.get('natTargets', []):
                    if nat.get('addressTo', None) == '169.254.169.254':
                        return rule
        return None

    def show_instance_bridge_port_metadata_nat_rule(self, instance):
        rule = self.get_instance_bridge_port_metadata_nat_rule(instance)
        if rule:
            self.show_rules(rule)
        else:
            self.log.debug('No Rules Found')

    def get_clc_veth_for_subnet(self, subnet):
        if not subnet:
            raise ValueError('get_clc_veth_for_subnet(). Subnet not provided')
        if not isinstance(subnet, basestring):
            subnet = subnet.id
        subnet = str(subnet).replace('subnet-', 'vn0_')
        self.eucaconnection.clc_machine.sys('ifconfig | grep {0}'.format(subnet), code=0)

    def get_clc_veth_for_vpc(self, vpc):
        if not vpc:
            raise ValueError('get_clc_veth_for_vpc(). VPC not provided')
        if not isinstance(vpc, basestring):
            vpc = vpc.id
        vpc = str(vpc).replace('vpc-', 'vn2_')
        self.eucaconnection.clc_machine.sys('ifconfig | grep {0}'.format(vpc), code=0)

    def get_euca_vpc_gateway_mido_hosts(self):
        gws = self.get_euca_vpc_gateway_info()
        hosts = self.mapi.get_hosts(query=None)
        mido_gw_hosts = []
        for gw in gws:
            gw_hostname = gw.get('GatewayHost', None)
            if gw_hostname:
                for host in hosts:
                    if gw_hostname == host.get_name():
                        mido_gw_hosts.append(host)
                        break
        return mido_gw_hosts

    def show_gateway_hosts(self):
        hosts = self.get_euca_vpc_gateway_mido_hosts()
        self.show_hosts(hosts=hosts)

    def get_euca_vpc_gateway_info(self):
        midocfg = self.get_euca_mido_config()
        gatewayhost = midocfg.get('GatewayHost', None)
        if gatewayhost:
            gw = {'GatewayHost': gatewayhost}
            gw['GatewayIP'] = midocfg.get('GatewayIP', None)
            gw['GatewayInterface'] = midocfg.get('GatewayInterface', None)
            return [gw]
        return midocfg.get('Gateways', {})


    def get_euca_mido_config(self):
        propname = 'cloud.network.network_configuration'
        prop = self.eucaconnection.get_property(property=propname)
        if not prop:
            raise ValueError('Euca Property not found: {0}'.format(propname))
        value = json_loads(prop.value)
        mido_config = value.get('Mido', {})
        if not mido_config:
            self.log.warning("Mido config section not found in euca nework_configuration "
                             "property")
        return mido_config


    def set_bgp_for_peer_via_cli(self, router_name, port_ip, local_as, remote_as, peer_address, route):
        raise NotImplementedError('Not implemented yet')

    def _show_midolman_config_dict(self, config_dict, section=None, printmethod=None, printme=True):
        table_width = 100
        key_len = 24
        val_len = table_width - key_len - 3
        buf = ""
        for section_name, opt_dict in config_dict.iteritems():
            if section and section_name != section:
                continue
            else:
                buf += markup("\n{0}\n".format(section_name),
                              [TextStyle.BOLD, TextStyle.UNDERLINE,
                               ForegroundColor.WHITE, BackGroundColor.BG_BLUE])
                pt = PrettyTable(['key', 'value'])
                pt.max_width['key'] = key_len
                pt.max_width['value'] = val_len
                pt.align = 'l'
                pt.border = False
                pt.header = False
                for key, val in opt_dict.iteritems():
                    pt.add_row([str(key).ljust(key_len), str(val).ljust(val_len)])
                buf += "{0}\n".format(pt)
        if printme:
            printmethod = printmethod or self.log.info
            printmethod(buf)
        else:
            return buf

    def show_mido_conf_for_hosts(self, hosts=None, path='/etc/midolman.conf', username=None,
                              password=None, keypath=None, sshtimeout=10, printmethod=None):
        printmethod = printmethod or self.log.info
        if not hosts:
            try:
                hosts = self.get_midolman_hosts_from_zk()
            except Exception as E:
                self.log.warning('Failed to fetch midolman hosts from zk: {0}'.format(E))
                try:
                    hosts = self.mapi.get_hosts()
                except Exception as E:
                    self.log.warning('Failed to fetch hosts from Midolman api: {0}'.format(E))
        if not hosts:
            raise ValueError('No hosts were provided, and none could be found')
        if not isinstance(hosts, list):
            hosts = [hosts]
        buf = "\n"
        for host in hosts:
            ssh_host = None
            error = None
            try:
                if isinstance(host, Host):
                    host = host.get_name()
                ssh = self.get_host_ssh(host, username=username, password=password,
                                        keypath=keypath, timeout=sshtimeout)
                ssh_host = ssh.host
                config = self.get_midolman_conf(ssh=ssh)
            except Exception as E:
                error = markup('ERROR fetching config:"{0}"\n'.format(E),
                               [BackGroundColor.BG_WHITE, ForegroundColor.RED])
            buf += "-".ljust(80, "-")
            buf += markup('\n\nHOST: {0}\nIP: {1}\nPATH: {2}\n'.format(host, ssh_host, path),
                         [TextStyle.BOLD, BackGroundColor.BG_BLACK,
                          ForegroundColor.WHITE])
            if error:
                buf += error
            else:
                buf += self._show_midolman_config_dict(config, printme=False)
        printmethod(buf)

    def get_midolman_conf(self, ssh=None, mido_conf='/etc/midolman/midolman.conf', verbose=True):
        ssh = ssh or self.eucaconnection.clc_machine.ssh
        buf = ""
        start = False
        config_dict = {}
        for line in ssh.sys('cat {0}'.format(mido_conf), code=0, listformat=True, verbose=verbose):
            if verbose:
                self.log.debug(line)
            if re.search("^\[*.*\]\s*$", line):
                start = True
            if start:
                buf += line + "\n"
        if buf:
            sio = StringIO(unicode(buf))
            try:
                config = ConfigParser()
                config.readfp(sio)
            finally:
                if sio:
                    sio.close()
            for section in config.sections():
                config_dict[section] = dict(config.items(section))
        else:
            self.log.warning('Midonet Config buffer empty')
        return config_dict

    def get_zk_hosts_from_config(self, mido_config=None):
        mido_config = mido_config or self.get_midolman_conf()
        # Get the zookeeper section from a midolman.conf dictionary
        zk_section = mido_config.get('zookeeper')
        zk_hosts_string = zk_section.get('zookeeper_hosts', None)
        hosts = []
        if not zk_hosts_string:
            self.log.warn('No zookeeper_hosts option found in mido config dictionary')
        else:
            hosts = zk_hosts_string.split(',')
        return hosts


    def show_zk_hosts(self, hosts=None, printmethod=None, printme=True):
        hosts = hosts or self.get_zk_hosts_from_config()
        pt = PrettyTable(['HOST', 'PORT', 'STATUS(is ok?)'])
        for host in hosts:
            status = None
            try:
                client = KazooClient(host)
                client.start()
            except Exception as E:
                status = 'Error creating and starting zookeeper client ' \
                         'for host: "{0}", err:"{1}"'.format(host, E)

            host, port = client.hosts[0]
            if not status:
                status = client.command('ruok')
            pt.add_row([host, port, status])
        if printme:
            printmethod = printmethod or self.log.info
            printmethod("\n{0}\n".format(pt))
        else:
            return pt

    def get_zk_client(self, hosts=None):
        if not hosts:
            hosts = self.get_zk_hosts_from_config()
            if not hosts:
                raise ValueError('No zookeeper hosts provided and none found?')
            hosts = ", ".join(hosts)
        client = KazooClient(hosts)
        self.log.debug('Attempting to start zk client with hosts:"{0}"'.format(hosts))
        client.start()
        return client

    def get_midolman_hosts_from_zk(self):
        zk = self.get_zk_client()
        hostnames = []
        host_ids = zk.get_children('/midonet/v1/hosts/') or []
        for id in host_ids:
            data_str, znodstat = zk.get('/midonet/v1/hosts/' + id)
            if data_str:
                data = json.loads(data_str)
                if data:
                    data = data.get('data', {})
                    hostname = data.get('name' or None)
                    if hostname:
                        hostnames.append(hostname)
        return hostnames

    def get_midolman_config_from_zk(self, nodes=None):
        nodes = nodes or ['nsdb', 'cluster', 'agent']
        if not isinstance(nodes, list):
            nodes = [nodes]
        zk = self.get_zk_client()
        buf = ""
        for node in nodes:
            conf =  zk.get('/midonet/v1/config/schemas/{0}'.format(node))
            if conf:
                buf += conf[0]
        return buf

    def show_midolman_bundled_zk_config(self, nodes=None, printmethod=None):
        printmethod = printmethod or self.log.info
        printmethod("\n{0}\n".format(self.get_midolman_config_from_zk(nodes=nodes)))










