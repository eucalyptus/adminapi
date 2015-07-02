
import json
import re
import socket
import subprocess
import sys
import time
import threading
from cloud_utils.system_utils import local
from cloud_utils.net_utils.ip_rx import remote_receiver, START_MESSAGE
from cloud_utils.net_utils.ip_tx import remote_sender
from cloud_utils.net_utils.sshconnection import SshCbReturn


def test_port_status(ip,
                     port,
                     timeout=5,
                     tcp=True,
                     recv_size=0,
                     send_buf=None,
                     debug=None,
                     verbose=True):
        '''
        Attempts to connect to tcp port at ip:port within timeout seconds

        :param ip: remote ip/hostname to attempt to connect to
        :param port: remote port to connect to
        :param tcp: Use tcp in this test
        :param recv_size: size of buffer to read from socket
        :param send_buf: buffer to send
        :param debug: bool, print debug info w/ 'print'
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

        debug('test_port_status, ip:'+str(ip)+', port:'+str(port)+', TCP:'+str(tcp))
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
            debug('test_port_status failed socket error:'+str(se[0]))
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
                local("ping -c 1 " + address)
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
        rem_zero = network.replace('0','')
        if not re.search('\d', rem_zero):
            return True
        ipaddr = int(''.join([ '%02x' % int(x) for x in ip_addr.split('.') ]), 16)
        netstr, bits = network.split('/')
        netaddr = int(''.join([ '%02x' % int(x) for x in netstr.split('.') ]), 16)
        mask = (0xffffffff << (32 - int(bits))) & 0xffffffff
        return (ipaddr & mask) == (netaddr & mask)


def packet_test(sender_ssh, receiver_ssh, protocol, dest_ip=None, src_addrs=None,
                port=None, bind=False, count=1, payload=None, timeout=5, verbose=False):
    """
    Test utility to send and receive IP packets of varying protocol types, ports, counts, etc.
    between 2 remote nodes driven by the SSH connections provided. 

    :param sender_ssh: sshconnection object to send packets from
    :param receiver_ssh: sshconnection object to receive packets
    :param protocol: protocol number for packets ie: 1=icmp, 6=tcp, 17=udp, 132=sctp, etc..
    :param dest_ip: Optional IP for the sender to send packets to, defaults to receiver_ssh.host
    :param src_addrs: Source addresses the receiver will use to filter rx'd packets
    :param port: optional port to use for sending packets to
    :param bind: option to bind receiver to provided port, maybe needed to rx certain packet types
    :param count: number of packets to send and expect
    :param payload: optional payload to include in the sent packets (string buffer)
    :param timeout: time in seconds to allow
    :param verbose: boolean, used to control verbose logging of info
    :return: json result of receiver
    :raise RuntimeError:
    """
    dest_ip = dest_ip or receiver_ssh.host
    # Make sure the connections are active
    for ssh_connection in [sender_ssh, receiver_ssh]:
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
            # ret.removecb = True
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
        def __init__(self, ssh, dest_ip, proto, port=None, count=1, verbose=False):
            self.ssh = ssh
            self.dest_ip = dest_ip
            self.proto = proto
            self.port = port
            self.count = count
            self.result = None
            self.done_time = None
            self.verbose = verbose
            super(Sender, self).__init__()

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
                self.ssh.debug(buf)
            return ret

        def run(self):
            if self.verbose:
                self.ssh.debug('Starting Sender...\n')
            self.result = remote_sender(ssh=self.ssh, dst_addr=self.dest_ip, proto=self.proto,
                                        port=self.port, count=self.count, verbose=self.verbose,
                                        cb=self.packet_test_cb, cbargs=[verbose])
            self.done_time = time.time()

    tx = Sender(ssh=sender_ssh, dest_ip=dest_ip, proto=protocol, port=port, count=count,
                verbose=verbose)
    rx = Receiver(ssh=receiver_ssh, src_addrs=src_addrs, port=port, proto=protocol,
                  bind=bind, count=count,verbose=verbose, timeout=timeout, sender=tx)
    rx.run()

    if not isinstance(rx.result, dict):
        raise RuntimeError('Failed to read in results dict from remote receiver, output: {0}'
                           .format(rx.result))
    if verbose:
        json.dumps(rx.result, sort_keys=True, indent=4)
    return rx.result

