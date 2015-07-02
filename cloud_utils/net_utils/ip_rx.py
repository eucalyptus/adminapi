#!/usr/bin/python
'''
#
# Simple IP packet server/listener test tool
#
Results are returned in JSON format containing the following attributes:
 count = number of packets captured using the filters provided
 elapsed = time in seconds for this capture
 name = Name of this capture test, defaults to the current date/time
 packets = dict of packets in the format: [src addr][dst addr][port] = packet count

Examples:
# Listen for all sctp(proto 132), filter for dest ports; 101, 102, 103, wait for no more than
# 20 seconds and no more than 5 packets, set verbose level to 0 for quiet:

./ip_rx.py -o 132 -p 101,102,103 -t 20 -c 5 -v0
{
    "count": 6,
    "elapsed": 8.9399999999999995,
    "name": "Mon Jun 22 22:25:41 2015",
    "packets": {
        "10.111.5.178": {
            "10.111.1.110": {
                "101": 1,
                "102": 1,
                "103": 4
            }
        }
    }
    "protocol": 132
}


# Listen for multicast address 228.7.7.3, dstport: 8773, from any of the
# following hosts; "10.111.1.110, 10.111.5.178", write results to file 'junk.txt',
# capture for no more than 15 seconds, if port is not specified 'unknown' will be
# used in the results output instead of a port number:

./ip_rx.py -o 17 -s "10.111.1.110, 10.111.5.178" -n "My test name" -f junk.txt -q -t 15 -v0
{
    "count": 22,
    "elapsed": 15.0,
    "name": "My test name",
    "packets": {
        "10.111.1.110": {
            "228.7.7.3": {
                "unknown": 5
            }
        },
        "10.111.5.178": {
            "10.111.1.110": {
                "unknown": 13
            },
            "228.7.7.3": {
                "unknown": 4
            }
        }
    }
    "protocol": 17
}


# Same as above but now with a port number...

./ip_rx.py -o 17 -s "10.111.1.110, 10.111.5.178" -n "TEST2" -f junk.txt -q -t 15 -p 8773 -v0
{
    "count": 14,
    "elapsed": 15.0,
    "name": "TEST2",
    "packets": {
        "10.111.1.110": {
            "228.7.7.3": {
                "8773": 3
            }
        },
        "10.111.5.178": {
            "10.111.1.110": {
                "8773": 9
            },
            "228.7.7.3": {
                "8773": 2
            }
        }
    }
    "protocol": 17
}

'''
from os.path import abspath, basename
import re
import socket
import sys
import traceback
import json
import struct
import time
from optparse import OptionParser
TRACE = 3
DEBUG = 2
INFO = 1
QUIET = 0
VERBOSE_LVL = INFO
START_MESSAGE = 'Begin Capture'


def get_script_path():
    try:
        import inspect
    except ImportError:
        return None
    # print os.path.abspath(inspect.stack()[0][1])
    # print inspect.getfile(inspect.currentframe())
    # print os.path.realpath(inspect.getfile(inspect.currentframe()))
    return abspath (inspect.stack()[0][1])


def sftp_file(sshconnection, verbose_level=DEBUG):
    script_path = get_script_path()
    script_name = basename(script_path)
    sshconnection.sftp_put(script_path, script_name)
    debug('Done Copying script:"{0}" to "{1}"'.format(script_name, sshconnection.host),
          verbose_level)
    return script_name

def print_help():
    p = get_option_parser()
    p.print_help()

def remote_receiver(ssh, src_addrs=None, proto=17, dst_addrs=None, port=None,
                    count=30, bind=False, timeout=15, cb=None, cbargs=None, verbose_level=DEBUG):
    script = sftp_file(ssh, verbose_level=verbose_level)
    cmd = "python {0} -o {1} -c {2} -v{3} ".format(script, proto, count, verbose_level)
    if src_addrs:
        cmd += " -s '{0}' ".format(src_addrs)
    if dst_addrs:
        cmd += " -d '{0}' ".format(dst_addrs)
    if port:
        cmd += " -p '{0}' ".format(port)
    if timeout:
        cmd += " -t {0} ".format(timeout)
    if bind:
        if port is None:
            raise ValueError('Need to provide port when using bind option')
        cmd += " --bind "
    cmddict = ssh.cmd(cmd, listformat=True, cb=cb, cbargs=cbargs, verbose=(verbose_level == 1))
    out = cmddict.get('output')
    if cmddict.get('status') != 0:
        raise RuntimeError('{0}\n"{1}" cmd failed with status:{2}, on host:{3}'
                           .format(out, cmd, cmddict.get('status'), ssh.host))
    try:
        lines = ""
        for line in out:
            if not re.search('^\s*#', line):
                lines += line + '\n'
        jout = json.loads(lines)
    except Exception as JE:
        jout =  '{0}\nJSON loads failed, error:{1}'.format(lines, JE)
        #raise
    return jout


def debug(msg, level=DEBUG):
    """
    Write debug info to stdout filtering on the set verbosity level and prefixing each line
    with a '#' to allow for easy parsing of results from output.
    :param msg: string to print
    :param level: verbosity level of this message
    :return: None
    """
    if not VERBOSE_LVL:
        return
    if VERBOSE_LVL >= level:
        for line in str(msg).splitlines():
            sys.stdout.write("# {0}\n".format(str(line)))


def get_proto_name(number):
    """
    Attempt to convert a protocol number into a known name

    :param number: int, protocol number
    :return: string, protocol name if found, else the number as a string
    """
    for proto, value in socket.__dict__.iteritems():
        if proto.startswith('IPPROTO_') and value == number:
            return str(proto).replace('IPPROTO_', '')
    return str(number)

def get_option_parser():
    parser = OptionParser()

    parser.add_option("-n", "--testname", dest="testname", default=None,
                      help="Name used to identify test results", metavar='TESTNAME')

    parser.add_option("-p", "--dst-ports", dest="destports", default='',
                      help="Comma separated list of Destination Ports to filter on, example:8773",
                      metavar='PORT')

    parser.add_option("-r", "--src-ports", dest="srcports", default="",
                      help="Comma separated list of Source Ports to filter on", metavar='PORT')

    parser.add_option("-o", "--proto", dest="proto", type="int", default=17,
                      help="Protocol type, examples: 6 for TCP, 17 for UDP.\n"
                           "Default: 132 for 'sctp'",
                      metavar='PROTO')

    parser.add_option("-t", "--timeout", dest="timeout", type="int", default=None,
                      help="Amount of time to collect packets'",
                      metavar='COUNT')

    parser.add_option("-c", "--count", dest="count", type="int", default=0,
                      help="Max packet count before exiting'",
                      metavar='COUNT')

    parser.add_option("-s", "--src-addrs", dest="srcaddrs", default="",
                      help="Comma delimited list of src ip addresses used to filter",
                      metavar="ADDRS")

    parser.add_option("-d", "--dst-addrs", dest="dstaddrs", default="",
                      help="Comma delimited list of dst ip addresses used to filter, "
                           "example: 228.7.7.3", metavar="ADDRS")

    parser.add_option("--bind", dest="bind", action='store_true', default=False,
                      help="Flag to enable port binding, default:false")

    parser.add_option("-v", "--verbose", dest="verbose", type='int', default=INFO,
                      help="Verbose level, 0=quiet, 1=info, 2=debug, 3=trace. Default=1")

    parser.add_option("-a", "--addr", dest="addr", default='',
                      help="Local addr to bind to, default is '' or 'listen on all'",
                      metavar='HOST')

    parser.add_option("-f", "--file", dest="resultsfile", default="",
                      help="File Path to save results to", metavar="ADDRS")
    return parser



##################################################################################################
#                                           IP HEADER
##################################################################################################


class IPHdr(object):
    def __init__(self, packet):
        """
        Simple class used to parse and represent an IP header.
        :param packet: Packet should be raw bytes read from socket, etc..
        """
        self.version = None
        self.header_len = None
        self.ttl = None
        self.protocol = None
        self.src_addr = None
        self.dst_addr = None
        self.parse_ip_hdr(packet)

    def parse_ip_hdr(self, packet):
        """
        Used to parse and populate attributes of the ip header
        :param packet: Packet should be raw bytes read from socket, etc..
        """
        ip_header = packet[0: 20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        version_ihl = iph[0]
        self.version = version_ihl >> 4
        ihl = version_ihl & 0xF
        self.header_len = ihl * 4
        self.ttl = iph[5]
        self.protocol = iph[6]
        self.src_addr = socket.inet_ntoa(iph[8])
        self.dst_addr = socket.inet_ntoa(iph[9])

    def print_me(self, verbose=INFO):
        """
        Print this IP header using the debug method
        :param verbose: verbosity level used to filter whether this gets printed or not
        """
        debug("IP ver:{0}, HDR LEN:{1}, TTL:{2}, PROTO:{3}, SRC ADDR:{4}, DST ADDR:{5}"
              .format(self.version, self.header_len, self.ttl, self.protocol, self.src_addr,
                      self.dst_addr), level=verbose)


###############################################################################################
#                       Start main socket listener routine...
###############################################################################################

if __name__ == "__main__":
    opt_parser = get_option_parser()
    options, args = opt_parser.parse_args()

    HOST = options.addr
    PROTO = options.proto
    if PROTO < 0 or PROTO > 254:
        raise ValueError('Invalid Protocol: "{0}"'.format(PROTO))
    BIND = options.bind
    COUNT = options.count
    if COUNT and COUNT < 0:
        raise ValueError('Count must be >= 0: "{0}"'.format(COUNT))
    VERBOSE_LVL = options.verbose
    TIMEOUT = options.timeout
    if TIMEOUT and TIMEOUT < 0:
        raise ValueError('If set, Timeout must be >= 0: "{0}"'.format(TIMEOUT))
    DSTPORTS = {}
    if options.destports:
        for port in options.destports.split(','):
            DSTPORTS[int(port)] = 0
    if len(DSTPORTS) > 1 and BIND:
        raise ValueError('Cannot use BIND option with more than one port at this time')
    SRCPORTS = {}
    if options.srcports:
        for port in options.srcports.split(','):
            SRCPORTS[int(port)] = 0
    SRCADDRS = {}
    if options.srcaddrs:
        for addr in options.srcaddrs.split(','):
            SRCADDRS[str(addr).strip()] = {}
    DSTADDRS = {}
    if options.dstaddrs:
        for addr in options.dstaddrs.split(','):
            DSTADDRS[str(addr).strip()] = {}

    if options.testname is None:
        options.testname = "PROTO:{0}, SRCADDRS:{1}, DSTADDRS:{2}, PORTS:{3}"\
            .format(PROTO, SRCADDRS, DSTADDRS, DSTPORTS)

    # Init results dict...
    results = {'packets': {},
               'protocol': PROTO,
               'elapsed': None,
               'count': None,
               'name': options.testname ,
               'error': '',
               'date': str(time.asctime())}

    sock = None
    file = None
    pkts = 0
    line = "--------------------------------------------------------------------------------"

    start = time.time()
    debug('{0} For Protocol:{1}/{2}'.format(START_MESSAGE, get_proto_name(PROTO), PROTO),
          level=INFO)

    try:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, PROTO)
        except socket.error as SE:
            if 'not permitted' in SE.strerror:
                try:
                    results['error'] += ('ERROR: This may need additional permission(s) to run? '
                                         'root, sudo, etc? Err:"{0}"\n'.format(SE))
                except:
                    pass
            raise
        if BIND:
            bport = DSTPORTS.iterkeys().next()
            debug("Binding to:'{0}':{1}".format(HOST, bport), DEBUG)
            sock.bind((HOST, bport))
        pkts = 0
        done = False
        time_remaining = TIMEOUT
        while not done:
            if TIMEOUT is not None:
                time_remaining = TIMEOUT - (time.time() - start)
                if time_remaining <= 0:
                    done = True
                    continue
            if COUNT == 0 or pkts < COUNT:
                if time_remaining is not None:
                    sock.settimeout(time_remaining)
                try:
                    data, (ip, info) = sock.recvfrom(65565)
                    if options.verbose >= TRACE:
                        sys.stdout.write('#')
                        sys.stdout.flush()
                except socket.timeout:
                    done = True
                    continue
                # Parse IP header...
                iphdr = IPHdr(data)

                # Check packet info against the provided filters...
                if PROTO and PROTO != iphdr.protocol:
                    continue
                if DSTPORTS:
                    srcport, dstport = struct.unpack('!HH',
                                                     data[iphdr.header_len:iphdr.header_len + 4])
                    if SRCPORTS and srcport not in SRCPORTS:
                        continue
                    if DSTPORTS and dstport not in DSTPORTS:
                        continue
                else:
                    srcport = 'unknown'
                    dstport = 'unknown'

                if ((not SRCADDRS or (iphdr.src_addr in SRCADDRS)) and
                        (not DSTADDRS or (iphdr.dst_addr in DSTADDRS))):
                    # Store info in results dict...
                    if iphdr.src_addr not in results['packets']:
                        results['packets'][iphdr.src_addr] = {}
                    if iphdr.dst_addr not in results['packets'][iphdr.src_addr]:
                        results['packets'][iphdr.src_addr][iphdr.dst_addr] = {}
                    if dstport not in results['packets'][iphdr.src_addr][iphdr.dst_addr]:
                        results['packets'][iphdr.src_addr][iphdr.dst_addr][dstport] = 1
                    else:
                        results['packets'][iphdr.src_addr][iphdr.dst_addr][dstport] += 1

                    # Print packet and debug info...
                    debug(line, INFO)
                    iphdr.print_me()
                    if DSTPORTS:
                        debug('Src Port:{0}, Dst Port:{1}'.format(srcport, dstport), INFO)
                    if not QUIET:
                        dlen = 0
                        plen = len(data)
                        if plen >= iphdr.header_len:
                            data = data[iphdr.header_len:]
                            dlen = len(data)
                        debug('From:{0}, Pkt:{1}, Data:{2}'.format(ip, plen, dlen), DEBUG)
                        debug('Info:{0}'.format(info), DEBUG)
                        debug('Data:{0}'.format(data), DEBUG)

                    # This packet met the provided filter criteria increment counter
                    pkts += 1
            else:
                done = True
    except KeyboardInterrupt:
        done = True
    except Exception as E:
        results['error'] += traceback.format_exc()
    finally:
        try:
            if sock:
                sock.close()
        except Exception as SE:
            debug('Error while closing socket:"{0}"'.format(SE), INFO)
        elapsed = "%.2f" % (time.time() - start)
        results['count'] = pkts
        results['elapsed'] = float(elapsed)
        # print "Packets:{0}, Time:{1}".format(pkts, elapsed)
        out = "\n{0}\n".format(json.dumps(results, indent=4, sort_keys=True))
        print out
        if options.resultsfile:
            with open(options.resultsfile, 'a+') as res_file:
                res_file.write(out)
                res_file.flush()