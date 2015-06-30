#!/usr/bin/python
"""
Simple packet generator/client test tool
"""
from os.path import abspath, basename
from random import getrandbits
import socket
import struct
import time
import sys
from optparse import OptionParser, OptionValueError
from crc32c import cksum
ICMP_ECHO_REQUEST = 8
ICMP_EHCO_REPLY = 0


def checksum(source_string):
    """
    From: https://github.com/samuel/python-ping
    Copyright (c) Matthew Dixon Cowles, <http://www.visi.com/~mdc/>.
    Distributable under the terms of the GNU General Public License
    version 2. Provided with no warranties of any sort.
    """
    # I'm not too confident that this is right but testing seems to
    # suggest that it gives the same answers as in_cksum in ping.c.
    sum = 0
    count_to = (len(source_string) / 2) * 2
    count = 0
    while count < count_to:
        this_val = ord(source_string[count + 1])*256+ord(source_string[count])
        sum = sum + this_val
        sum = sum & 0xffffffff # Necessary?
        count = count + 2
    if count_to < len(source_string):
        sum = sum + ord(source_string[len(source_string) - 1])
        sum = sum & 0xffffffff # Necessary?
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    # Swap bytes. Bugger me if I know why.
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def get_script_path():
    try:
        import inspect
    except ImportError:
        return None
    # print os.path.abspath(inspect.stack()[0][1])
    # print inspect.getfile(inspect.currentframe())
    # print os.path.realpath(inspect.getfile(inspect.currentframe()))
    return abspath (inspect.stack()[0][1])


def sftp_file(sshconnection):
    script_path = get_script_path()
    script_name = basename(script_path)
    sshconnection.sftp_put(script_path, script_name)
    print 'Done Copying script:"{0}" to "{1}"'.format(script_name, sshconnection.host)


def get_src(dest):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.connect((dest, 1))
    source_ip = s.getsockname()[0]
    s.close()
    return source_ip

def send_ip_packet(destip, proto=132, payload=None):
    s = None
    if payload is None:
            payload = 'IP TEST PACKET'
    payload = payload or ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
        s.sendto(payload, (destip, 0))
    except socket.error as SE:
        if SE.errno == 1 and 'not permitted' in SE.strerror:
            sys.stderr.write('Permission error creating socket, try with sudo, root...?\n')
        raise
    finally:
        if s:
            s.close()

def send_sctp_packet(destip, dstport=101, srcport=1000, proto=132, ptype=None, payload=None,
                     sctpobj=None):
    s = None
    if payload is None:
            payload = 'SCTP TEST PACKET'
    payload = payload or ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
        if not sctpobj:
            sctpobj = SCTP(srcport=srcport, dstport=dstport, ptype=ptype, payload=payload)
        s.sendto(sctpobj.pack(), (destip, dstport))
    except socket.error as SE:
        if SE.errno == 1 and 'not permitted' in SE.strerror:
            sys.stderr.write('Permission error creating socket, try with sudo, root...?\n')
        raise
    finally:
        if s:
            s.close()


def send_udp_packet(destip, dstport=101, proto=17, payload=None):
    s = None
    if payload is None:
            payload = 'UDP TEST PACKET'
    payload = payload or ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto)
        s.sendto(payload, (destip, dstport))
    except socket.error as SE:
        if SE.errno == 1 and 'not permitted' in SE.strerror:
            sys.stderr.write('Permission error creating socket, try with sudo, root...?\n')
        raise
    finally:
        if s:
            s.close()

def send_tcp_packet(destip, dstport=101, proto=6, payload=None, bufsize=4096):
    s = None
    if payload is None:
            payload = 'TCP TEST PACKET'
    payload = payload or ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto)
        s.connect((destip, dstport))
        s.send(payload)
        data = s.recv(bufsize)
    except socket.error as SE:
        if SE.errno == 1 and 'not permitted' in SE.strerror:
            sys.stderr.write('Permission error creating socket, try with sudo, root...?\n')
        raise

    finally:
        if s:
            s.close()
    return data

def send_icmp_packet(destip, icmptype=ICMP_ECHO_REQUEST, id=1234, seqnum=1, code=0, proto=1,
                     ptype=None, payload='ICMP TEST PACKET'):
    if payload is None:
            payload = 'ICMP TEST PACKET'
    payload = payload or ""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
        icmp = ICMP(destaddr=destip, id=id, seqnum=seqnum, code=code, icmptype=icmptype,
                    ptype=ptype, payload=payload)
        s.sendto(icmp.pack(), (destip, 0))
    except socket.error as SE:
        if SE.errno == 1 and 'not permitted' in SE.strerror:
            sys.stderr.write('Permission error creating socket, try with sudo, root...?\n')
        raise
    finally:
        if s:
            s.close()

def send_packet(destip, proto, dstport=345, ptype=None, payload=None):
    if proto in [1, 'icmp']:
        send_icmp_packet(destip=destip, ptype=ptype, payload=payload)
    elif proto in [6, 'tcp']:
        send_tcp_packet(destip=destip, dstport=dstport, payload=payload)
    elif proto in [17, 'udp']:
        send_udp_packet(destip=destip, dstport=dstport, payload=payload)
    elif proto in [132, 'sctp']:
        send_sctp_packet(destip=destip, ptype=ptype, dstport=dstport, payload=payload)
    else:
        send_ip_packet(destip=destip, proto=proto, payload=payload)

class ICMP(object):

    def __init__(self, destaddr, id=1234, seqnum=1, code=0, ptype=None,
                 payload=None):

        self.destaddr = destaddr
        if payload is None:
            payload = 'ICMP TEST PACKET'
        self.payload = payload or ""
        self.icmptype = ptype or ICMP_ECHO_REQUEST
        self.id = id
        self.code = code
        self.seqnum = seqnum

    def pack(self):
        tmp_checksum = 0
        header = struct.pack("bbHHh", self.icmptype, self.code, tmp_checksum, self.id, self.seqnum)
        fin_checksum = checksum(header + self.payload)
        header = struct.pack("bbHHh", self.icmptype, self.code, socket.htons(fin_checksum),
                             self.id, self.seqnum)
        packet = header + self.payload
        return packet


class InitChunk(object):
    def __init__(self, tag=None, a_rwnd=62464, outstreams=2, instreams=65535, tsn=None,
                 param_data=""):
        self.tag = tag or getrandbits(32)
        self.a_rwnd = a_rwnd
        self.outstreams = outstreams or 1 # 0 is invalid
        self.instreams = instreams or 1 # 0 is invalid
        self.tsn = tsn or self.tag
        self.param_data = param_data or ""

    def pack(self):
        packet = struct.pack('!IIHHI', self.tag, self.a_rwnd, self.outstreams, self.instreams,
                             self.tsn)
        if self.param_data:
            packet += self.param_data
        return packet


class DataChunk(object):
    def __init__(self, tsn=1, stream_id=12345, stream_seq=54321, payload_proto=0, payload=None):
        if payload is None:
            payload = "TEST SCTP DATA CHUNK"
        self.payload = payload
        self.tsn = tsn
        self.stream_id = stream_id
        self.stream_seq = stream_seq
        self.payload_proto = payload_proto

    @property
    def length(self):
        return 12 + len(self.payload)

    def pack(self):
        packet = struct.pack('!iHHi', self.tsn, self.stream_id, self.stream_seq,
                             self.payload_proto)
        packet += self.payload
        return packet


class HeartBeatChunk(object):
    def __init__(self, parameter=1, payload=None):
        self.parameter = parameter
        if payload is None:
            payload = str(getrandbits(64))
        self.hb_info = payload
        self.hb_info_length = 4 + len(payload)

    def pack(self):
        chunk = struct.pack('!HH', self.parameter, self.hb_info_length)
        chunk += self.hb_info
        return chunk


class ChunkHdr(object):
    def __init__(self, chunktype=None, flags=0, payload=None, chunk=None):
        if chunktype is None:
            chunktype = 1
        self.chunktype = chunktype
        self.chunkflags = flags
        if chunk:
            self.chunkobj = chunk
        elif chunktype == 0:
            self.chunkobj = DataChunk(payload=payload)
        elif chunktype == 1:
            self.chunkobj = InitChunk()
        elif chunktype == 4:
            self.chunkobj = HeartBeatChunk(payload=payload)
        self.chunk_data = self.chunkobj.pack()
        # SCTP header plus rest of packet = length?
        self.chunklength = 4 + len(self.chunk_data)

    def pack(self):
        chunk = struct.pack('!bbH', self.chunktype, self.chunkflags, self.chunklength)
        packet = chunk + self.chunk_data
        return packet


class SCTP(object):
    """
    Chunk Types
    0	DATA	Payload data
    1	INIT	Initiation
    2	INIT ACK	initiation acknowledgement
    3	SACK	Selective acknowledgement
    4	HEARTBEAT	Heartbeat request
    5	HEARTBEAT ACK	Heartbeat acknowledgement
    6	ABORT	Abort
    7	SHUTDOWN	Shutdown
    8	SHUTDOWN ACK	Shutdown acknowledgement
    9	ERROR	Operation error
    10	COOKIE ECHO	State cookie
    11	COOKIE ACK	Cookie acknowledgement
    12	ECNE	Explicit congestion notification echo (reserved)
    13	CWR	Congestion window reduced (reserved)
    14	SHUTDOWN COMPLETE

    Chunk Flags
    # I - SACK chunk should be sent back without delay.
    # U - If set, this indicates this data is an unordered chunk and the stream sequence number
          is invalid. If an unordered chunk is fragmented then each fragment has this flag set.
    # B - If set, this marks the beginning fragment. An unfragmented chunk has this flag set.
    # E - If set, this marks the end fragment. An unfragmented chunk has this flag set
    """
    def __init__(self, srcport, dstport, tag=None, ptype=None, payload=None, chunk=None):
        self.src = srcport
        self.dst = dstport
        self.checksum = 0
        self.tag = tag or getrandbits(16)
        chunk = chunk or ChunkHdr(chunktype=ptype, payload=payload)
        self.chunk = chunk.pack()

    def pack(self, src=None, dst=None, tag=None, do_checksum=True):
        src = src or self.src
        dst = dst or self.dst
        verification_tag = tag or self.tag
        packet = struct.pack('!HHII', src, dst, verification_tag, 0)
        chunk = self.chunk
        if not do_checksum:
            packet += chunk
            return packet
        pktchecksum = cksum(packet + chunk)
        # Rebuild the packet with the checksum
        packet = struct.pack('!HHII', src, dst,
                             verification_tag, pktchecksum)
        packet += chunk
        return packet


if __name__ == "__main__":

    parser = OptionParser()
    parser.add_option("-s", "--srcport", dest="src", type="int", default=1000,
                      help="Source SCTP Port", metavar='PORT')
    parser.add_option("-p", "--dstport", dest="dst", type="int", default=101,
                      help="Destination SCTP Port", metavar="PORT")
    parser.add_option("-d", "--dst", dest="destip", default=None,
                      help="Destination ip", metavar="IP")
    parser.add_option("--proto", dest="proto", type="int", default=132,
                      help="Protocol number(Examples: 1:icmp, 6:tcp, 17:udp, 132:sctp), "
                           "default:17", metavar="PROTOCOL")
    parser.add_option("-l", "--payload", dest="payload", default=None,
                      help="Chunk, data, payload, etc", metavar="DATA")

    options, args = parser.parse_args()
    if not options.destip:
        raise OptionValueError("'-d / --dst' for destination IP/Addr must be provided")
    destip = options.destip
    proto = options.proto
    srcport = int(options.src)
    dstport = int(options.dst)
    payload = options.payload
    if proto in [1, 'icmp']:
        send_icmp_packet(destip=destip, payload=payload)
    elif proto in [6, 'tcp']:
        send_tcp_packet(destip=destip, dstport=dstport, payload=payload)
    elif proto in [17, 'udp']:
        send_udp_packet(destip=destip, dstport=dstport, payload=payload)
    else:
        send_ip_packet(destip=destip, proto=proto, payload=payload)
