
import json
import re
import socket
import subprocess
import sys
import time
import threading
from cloud_utils.system_utils import local
from cloud_utils.log_utils import get_traceback
from cloud_utils.net_utils.ip_rx import remote_receiver, START_MESSAGE
from cloud_utils.net_utils.ip_tx import remote_sender, send_packet
from cloud_utils.net_utils.sshconnection import SshCbReturn, SshConnection


def test_port_status(ip,
                     port,
                     timeout=5,
                     tcp=True,
                     recv_size=0,
                     send_buf=None,
                     debug=None,
                     logger=None,
                     verbose=True):
        '''
        Attempts to connect to tcp port at ip:port within timeout seconds

        :param ip: remote ip/hostname to attempt to connect to
        :param port: remote port to connect to
        :param tcp: Use tcp in this test
        :param recv_size: size of buffer to read from socket
        :param send_buf: buffer to send
        :param debug: debug method or print debug info w/ 'print'
        :param verbose: bool, print verbose info
        :returns buffer read in
        '''
        ret_buf = ""
        if verbose:
            if not debug:
                def debug(msg):
                    print str(msg)
        else:
            def debug(msg):
                pass

        debug('test_port_status, ip:' + str(ip) + ', port:' + str(port) + ', TCP:' + str(tcp))
        if tcp:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.settimeout(timeout)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            if tcp:
                s.connect((ip, port))
            else:
                # for UDP always try send
                if send_buf is None:
                    send_buf = "--TEST LINE--"
            if send_buf is not None:
                s.sendto(send_buf, (ip, port))
            if recv_size:
                ret_buf = s.recv(recv_size)
        except socket.error, se:
            debug('test_port_status failed socket error:' + str(se[0]))
            # handle specific errors here, for now just for debug...
            ecode = se[0]
            if ecode == socket.errno.ECONNREFUSED:
                debug("test_port_status: Connection Refused")
            if ecode == socket.errno.ENETUNREACH:
                debug("test_port_status: Network unreachable")
            if ecode == socket.errno.ETIMEDOUT or ecode == "timed out":
                debug("test_port_status: Connect to " + str(ip) + ":" + str(port) + " timed out")
            raise se
        except socket.timeout, st:
            debug('test_port_status failed socket timeout')
            raise st
        finally:
            s.settimeout(None)
            s.close()
        debug('test_port_status, success')
        return ret_buf


def scan_port_range(ip, start, stop, timeout=1, tcp=True):
    '''
    Attempts to connect to ports, returns list of ports which accepted a connection

    :param ip: remote ip to scan
    :param start: lower end of port range to scan
    :param stop: upper end of port range to scan
    :param timeout: int timeout in seconds per port being scanned
    :param tcp: bool, if true TCP is used, else UDP
    :return list of ports which did not fault (connected) during scan
    '''
    ret = []
    for x in xrange(start, stop+1):
        try:
            sys.stdout.write("\r\x1b[K"+str('scanning:'+str(x)))
            sys.stdout.flush()
            test_port_status(ip, x, timeout=timeout, tcp=tcp, verbose=False)
            ret.append(x)
        except socket.error, se:
            pass
    return ret


def ping(address, poll_count=10, interval=2, logger=None):
        """
        :param: Ping an IP and poll_count times (Default = 10)
        :param: address      Hostname to ping
        :param: poll_count   The amount of times to try to ping the hostname with interval second
                     gaps in between
        :param: logger: optional logger to send debug and critical output to
        :returns: boolean True if ping succeeds, else false for failure
        """
        if logger:
            critical = logger.critical
            debug = logger.debug
        else:
            def debug(msg):
                print str(msg)

            def critical(msg):
                print sys.stderr, str(msg)

        if re.search("0.0.0.0", address):
            critical("Address is all 0s and will not be able to ping it")
            return False
        debug("Attempting to ping " + address)
        for x in xrange(0, poll_count):
            if x:
                debug('sleeping for {0} seconds'.format(interval))
                time.sleep(interval)
            try:
                local("ping -c 1 " + address, print_method=critical)
                debug("Was able to ping address")
                return True
            except subprocess.CalledProcessError as CPE:
                debug('Output:' + str(CPE.output))
                debug('Ping attempt {0}/{1} failed, err:{2}'
                      .format(x, poll_count, str(CPE)))
        critical("Was unable to ping address")
        return False


def is_address_in_network(ip_addr, network):
        """

        :param ip_addr: Ip address ie: 192.168.1.5
        :param network: Ip network in cidr notation ie: 192.168.1.0/24
        :return: boolean true if ip is found to be in network/mask, else false
        """
        ip_addr = str(ip_addr)
        network = str(network)
        # Check for 0.0.0.0/0 network first...
        rem_zero = network.replace('0', '')
        if not re.search('\d', rem_zero):
            return True
        ipaddr = int(''.join(['%02x' % int(x) for x in ip_addr.split('.')]), 16)
        netstr, bits = network.split('/')
        netaddr = int(''.join(['%02x' % int(x) for x in netstr.split('.')]), 16)
        mask = (0xffffffff << (32 - int(bits))) & 0xffffffff
        return (ipaddr & mask) == (netaddr & mask)

def get_network_info_for_cidr(network_cidr):
    ret = {'network_cidr': network_cidr,
           'netmask': [0, 0, 0, 0],
           'network': [],
           'broadcast': [],
           'max_addrs': 0,
           'max_subnets': 0}
    network, cidr = network_cidr.split('/')
    network = network.split('.')
    cidr = int(cidr)
    ret['max_subnets'] = pow(2, 32 - cidr)
    ret['max_addrs'] = ret['max_subnets']
    if ret['max_subnets'] > 2:
        ret['max_addrs'] -= 2
    for i in range(cidr):
        ret['netmask'][i / 8] = ret['netmask'][i / 8] + (1 << (7 - i % 8))
    for i in range(len(network)):
        ret['network'].append(int(network[i]) & ret['netmask'][i])
    ret['broadcast'] = list(ret['network'])
    for i in range(32 - cidr):
        ret['broadcast'][3 - i / 8] = ret['broadcast'][3 - i / 8] + (1 << (i % 8))
    for key, value in ret.iteritems():
        if isinstance(value, list):
            ret[key] = ".".join(str(x) for x in value)
    return ret



def packet_test(sender_ssh, receiver_ssh, protocol, dest_ip=None, src_addrs=None,
                port=None, src_port=None, bind=False, count=1, interval=.1, payload=None,
                timeout=5, verbose=False):
    """
    Test utility to send and receive IP packets of varying protocol types, ports, counts, etc.
    between 2 hosts. The sender can either be the local machine (by providing 'None' for the
    'sender_ssh' arg, or a remote machine by providing an SshConnection obj, the receiver
    is an SshConnection obj. To make the local machine the receiver, create in SshConnection obj
    using local host for this arg. The test will sftp the ip_tx.py and ip_rx.py test scripts to
    the respective ssh hosts and then perform a send -> receive packet test based on the criteria
    provided in the args/kwargs. The test returns the results in dict format. The 'packet'
    dict returned is in the format: packets: { src_ip: { dest_ip: { port: count}}}

    # Example sending an icmp packet from the local machine to a remote ssh 'ins2.ssh'
    # with results:

    >>packet_test(None, ins2.ssh, protocol=1, count=2, timeout=10, dest_ip=ins2.ip_address)

        {u'count': 2,  # Number of packets received which met filter criteria
         u'date': u'Wed Jul  8 03:23:31 2015',  # Timestamp of capture
         u'elapsed': 0.13,  # time elapsed for capture
         u'error': u'', # Any errors which were caught during the capture
         u'name': u'PROTO:1, SRCADDRS:{}, DSTADDRS:{}, PORTS:{}', # Name of this capture test
         u'packets': {u'10.5.1.86': {u'10.111.75.155': {u'unknown': 2}}}, # Dict of packets in
         u'protocol': 1} # protocol number/id

    # Example 1) UDP test between 2 remote hosts using:
    #    - the UDP protocol number 17
    #    - port 101
    #    - 10 packets
    >>packet_test(ssh_tx, ssh_rx, protocol=17, port=101, count=10, timeout=10, verbose=False)

    # Example 2) SCTP between 2 eutester Instance objects using:
    #    -the SCTP protocol number 132
    #    -sending to the instance's private ip address
    #    -filtering on the senders ip address
    #    -binding the receiver to the provided port
    >> packet_test(ins1.ssh, ins2.ssh, protocol=132, port=100, count=2,
                   dest_ip=ins2.private_ip_address, src_addrs=ins1.ip_address, bind=True)

    :param sender_ssh: sshconnection object to send packets from, if this is 'None' then
                       packets will be sent from the local machine instead
    :param receiver_ssh: sshconnection object to receive packets
    :param protocol: protocol number for packets ie: 1=icmp, 6=tcp, 17=udp, 132=sctp, etc..
    :param dest_ip: Optional IP for the sender to send packets to, defaults to receiver_ssh.host
    :param src_addrs: Source addresses the receiver will use to filter rx'd packets
                      Multiple addresses can be provided per comma delimited string
    :param port: optional port to use for sending packets to
    :param bind: option to bind receiver to provided port, maybe needed to rx certain packet types
    :param count: number of packets to send and expect
    :param interval: time to pause between sending packets, default=.1 seconds.
    :param payload: optional payload to include in the sent packets (string buffer)
    :param timeout: time in seconds to allow
    :param verbose: boolean, used to control verbose logging of info
    :return: json result of receiver
    :raise RuntimeError:
    """
    dest_ip = dest_ip or receiver_ssh.host
    # Make sure the connections are active
    for ssh_connection in [sender_ssh, receiver_ssh]:
        if ssh_connection is not None:
            if not ssh_connection.connection._transport.isAlive():
                ssh_connection.refresh_connection()

    class Receiver(object):
        def __init__(self, ssh, sender, src_addrs=None, port=None, proto=None, bind=False, count=1,
                     verbose=False, timeout=5):
            self.ssh = ssh
            self.src_addrs = src_addrs
            self.port = port
            self.proto = proto
            self.bind = bind
            self.count = count
            self.timeout = timeout
            self.sender = sender
            self.verbose = verbose
            if verbose:
                self.verbose_level = 1
            else:
                self.verbose_level = 2
            self.result = None

        def packet_test_cb(self, buf, *args):
            """
            Used to trigger packet sender when receiver is ready,
            """
            ret = SshCbReturn()
            ret.buf = buf
            ret.nextargs = args
            sender = args[0]
            if re.search(START_MESSAGE, buf):
                sender.start()
            if sender.done_time:
                if verbose:
                    self.ssh.debug('Sender is Done. Setting command timer to 5 seconds')
                ret.settimer = 5
            if verbose:
                self.ssh.debug(buf)
            return ret

        def run(self):
            if self.verbose:
                self.ssh.debug('Starting receiver...\n')
            self.result = remote_receiver(ssh=self.ssh, src_addrs=self.src_addrs,
                                          port=self.port, proto=self.proto,
                                          bind=self.bind, count=self.count,
                                          verbose_level=self.verbose_level,
                                          cb=self.packet_test_cb,
                                          cbargs=(self.sender, self.verbose),
                                          timeout=timeout)

    class Sender(threading.Thread):
        def __init__(self, ssh, dest_ip, proto, port=None, srcport=None, count=1, interval=.1,
                     verbose=False, socktimeout=None):
            self.ssh = ssh
            self.dest_ip = dest_ip
            self.proto = proto
            self.port = port
            self.srcport = srcport
            self.count = count
            self.error = None
            self.result = None
            self.done_time = None
            self.interval = interval
            self.socktimeout = socktimeout
            self.verbose = verbose
            super(Sender, self).__init__()

        def debug(self, msg):
            if self.ssh:
                return self.ssh.debug(msg)
            else:
                sys.stdout.write(msg)
                sys.stdout.flush()

        def packet_test_cb(self, buf, *args):
            """
            Used to trigger packet sender when receiver is ready,
            """
            ret = SshCbReturn()
            ret.buf = buf
            # ret.removecb = True
            ret.nextargs = args
            verbose = args[0]
            if verbose:
                self.debug(buf)
            return ret

        def run(self):
            if self.verbose:
                self.debug('Starting Sender...\n')
            if self.ssh is None:
                send_packet(destip=self.dest_ip, proto=self.proto, dstport=self.port,
                            count=self.count, interval=interval, verbose=self.verbose)
            else:
                try:
                    self.result = remote_sender(ssh=self.ssh, dst_addr=self.dest_ip, proto=self.proto,
                                                port=self.port, srcport=self.srcport, count=self.count,
                                                interval=interval, verbose=self.verbose,
                                                socktimeout=self.socktimeout, cb=self.packet_test_cb,
                                                cbargs=[verbose])
                except Exception as E:
                    self.error = "{0}\nERROR IN PACKET SENDER:{1}".format(get_traceback(), str(E))
            self.done_time = time.time()

    socktimeout = timeout - 1
    if socktimeout < 1:
        socktimeout = 1
    tx = Sender(ssh=sender_ssh, dest_ip=dest_ip, proto=protocol, port=port, srcport=src_port,
                count=count, interval=interval, verbose=verbose, socktimeout=socktimeout)
    rx = Receiver(ssh=receiver_ssh, src_addrs=src_addrs, port=port, proto=protocol, bind=bind,
                  count=count, verbose=verbose, timeout=timeout, sender=tx)
    rx.run()
    if not isinstance(rx.result, dict):
        errmsg = ""
        if tx.error:
            errmsg = "ERROR ON SENDER:{1}\n".format(tx.error)
        errmsg += 'Failed to read in results dict from remote receiver, output: {0}'\
            .format(rx.result)
        raise RuntimeError(errmsg)
    if verbose:
        json.dumps(rx.result, sort_keys=True, indent=4)
    return rx.result
