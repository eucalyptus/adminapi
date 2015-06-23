#!/usr/bin/python
'''
#
# Simple SCTP server/listener
#
'''
import copy
import select
import socket
import sys
import json
import struct
import time
from optparse import OptionParser


parser = OptionParser()

parser.add_option("-n", "--testname", dest="testname", default=str(time.asctime()),
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
                  help="Comma delimited list of src ip addresses used to filter", metavar="ADDRS")

parser.add_option("-d", "--dst-addrs", dest="dstaddrs", default="",
                  help="Comma delimited list of dst ip addresses used to filter, "
                       "example: 228.7.7.3", metavar="ADDRS")

parser.add_option("--bind", dest="bind", action='store_true', default=False,
                  help="Flag to enable port binding, default:false")

parser.add_option("-q", "--quiet", dest="quiet", action='store_true', default=False,
                  help="Flag to run in quiet mode and show ip info only")

parser.add_option("-a", "--addr", dest="addr", default='',
                  help="Local addr to bind to, default is '' or 'listen on all'", metavar='HOST')

parser.add_option("-f", "--file", dest="resultsfile", default="",
                  help="File Path to save results to", metavar="ADDRS")
options, args = parser.parse_args()

HOST = options.addr
PROTO = options.proto
BIND = options.bind
COUNT = options.count
QUIET = options.quiet
TIMEOUT = options.timeout
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
results = {'packets': {}, 'elapsed': None, 'count': None, 'name': options.testname}
sock = None
file = None

def debug(msg):
    for line in str(msg).splitlines():
        print "# {0}".format(str(line))



class IPHdr(object):
    def __init__(self, packet):
        self.version = None
        self.header_len = None
        self.ttl = None
        self.protocol = None
        self.src_addr = None
        self.dst_addr = None
        self.parse_ip_hdr(packet)

    def parse_ip_hdr(self, packet):
        ip_header = packet[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)
        version_ihl = iph[0]
        self.version = version_ihl >> 4
        ihl = version_ihl & 0xF
        self.header_len = ihl * 4
        self.ttl = iph[5]
        self.protocol = iph[6]
        self.src_addr = socket.inet_ntoa(iph[8]);
        self.dst_addr = socket.inet_ntoa(iph[9]);

    def print_me(self):
        debug("IP ver:{0}, HDR LEN:{1}, TTL:{2}, PROTO:{3}, SRC ADDR:{4}, DST ADDR:{5}"
            .format(self.version, self.header_len, self.ttl, self.protocol, self.src_addr,
                    self.dst_addr))

line = "----------------------------------------------------------------------------------"
start = time.time()

if not QUIET:
    debug('Opening Socket for Protocol:{0}'.format(PROTO))

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, PROTO)
    if BIND:
        bport = DSTPORTS.iterkeys().next()
        debug("Binding to:'{0}':{1}".format(HOST, bport))
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
        if COUNT == 0 or pkts <= COUNT:
            if time_remaining is not None:
                sock.settimeout(time_remaining)
            try:
                data, (ip, info) = sock.recvfrom(65565)
                sys.stdout.write('#')
                sys.stdout.flush()
            except socket.timeout:
                done = True
                continue
            iphdr = IPHdr(data)
            if DSTPORTS:
                srcport, dstport = struct.unpack('!HH',
                                                 data[iphdr.header_len:iphdr.header_len + 4])
                if SRCPORTS and srcport not in SRCPORTS:
                    continue
                if DSTPORTS and dstport not in DSTPORTS:
                    continue
            else:
                srcport = None
                dstport = None

            if ((not SRCADDRS or (iphdr.src_addr in SRCADDRS)) and
                    (not DSTADDRS or (iphdr.dst_addr in DSTADDRS))):
                if iphdr.src_addr not in results['packets']:
                    results['packets'][iphdr.src_addr] = {}
                if iphdr.dst_addr not in results['packets'][iphdr.src_addr]:
                    results['packets'][iphdr.src_addr][iphdr.dst_addr] = {}
                if dstport not in results['packets'][iphdr.src_addr][iphdr.dst_addr]:
                    results['packets'][iphdr.src_addr][iphdr.dst_addr][dstport] = 1
                else:
                    results['packets'][iphdr.src_addr][iphdr.dst_addr][dstport] += 1
                debug(line)
                iphdr.print_me()
                if DSTPORTS:
                    debug('Src Port:{0}, Dst Port:{1}'.format(srcport, dstport))
                if not QUIET:
                    dlen = 0
                    plen = len(data)
                    if plen >= iphdr.header_len:
                        data = data[iphdr.header_len:]
                        dlen = len(data)
                    debug('From:{0}, Pkt:{1}, Data:{2}'.format(ip, plen, dlen))
                    debug('Info:{0}'.format(info))
                    debug('Data:{0}'.format(data))
                debug(line)
                pkts += 1
        else:
            done = True
except KeyboardInterrupt:
    done = True
finally:
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
    if sock:
        sock.close()

