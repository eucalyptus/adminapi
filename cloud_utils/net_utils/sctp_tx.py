#!/usr/bin/python
"""


#!/usr/bin/python
'''
#
# Simple SCTP server/listener
#
'''
import socket
from optparse import OptionParser


parser = OptionParser()
parser.add_option("-p", "--port", dest="port", type="int", default=101,
                  help="Local SCTP Port to bind to", metavar='PORT')

parser.add_option("-a", "--addr", dest="addr", default='',
                  help="Local addr to bind to, default is '' or 'listen on all'", metavar='HOST')
options, args = parser.parse_args()

HOST = options.addr
PORT = options.port
#HOST = socket.gethostbyname(socket.gethostname())
try:
    conn = None
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 132)
    s.bind((HOST, PORT))
    while True:
        data, (ip, info) = s.recvfrom(1024)
        plen = len(data)
        dlen = 0
        if plen >= 48:
            data = data[48:]
            dlen = len(data)
        print "------------------------------------------------------"
        print 'From:{0}, Pkt:{1}, Data:{2}'.format(ip, plen, dlen)
        print 'Data:{0}'.format(data)
        print "------------------------------------------------------"
except Exception as E:
    if conn:
        conn.close()
    raise
if conn:
    conn.close()
"""

import socket
import struct
import time
import sys
from optparse import OptionParser, OptionValueError


def get_src(dest):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.connect((dest,1))
    source_ip = s.getsockname()[0]
    s.close()
    return source_ip

def send_packet(destip, dstport=101, srcport=1000, proto=132, payload=None):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
    except socket.error as SE:
        if SE.errno == 1 and 'not permitted' in SE.strerror:
            sys.stderr.write('Permission error creating socket, try with sudo, root...?\n')
        raise
    sctpobj = SCTP(srcport=srcport, dstport=dstport, payload=payload)
    s.sendto(sctpobj.pack(), (destip, dstport))

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
    def __init__(self, srcport, dstport, payload=None, chunk=None):
        self.src = srcport
        self.dst = dstport
        self.checksum = 0
        self.chunk = chunk or ChunkHdr(payload=payload)

    def pack(self, src=None, dst=None):
        src = src or self.src
        dst = dst or self.dst
        verification_tag = time.time()
        packet = struct.pack('!HHii', src, dst,
                             verification_tag, 0)
        packet += self.chunk.pack()
        return packet


class ChunkHdr(object):
    def __init__(self, chunktype=0, flags=0, payload=None, chunk=None):
        self.chunktype = chunktype
        self.chunkflags = 0
        self.chunkdataobj = chunk or DataChunk(payload=payload)
        self.chunk_data = self.chunkdataobj.pack()
        self.chunklength = 4 + self.chunkdataobj.length

    def pack(self):
        chunk = struct.pack('!bbH', self.chunktype, self.chunkflags, self.chunklength)
        packet = chunk + self.chunk_data
        return packet

class DataChunk(object):
    def __init__(self, tsn=1, stream_id=12345, stream_seq=54321, payload_proto=0, payload=None):
        if payload is None:
            payload ="TEST SCTP DATA CHUNK"
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


if __name__=="__main__":

    parser = OptionParser()
    parser.add_option("-s", "--srcport", dest="src", type="int", default=1000,
                      help="Source SCTP Port", metavar='PORT')
    parser.add_option("-p", "--dstport", dest="dst", type="int", default=101,
                      help="Destination SCTP Port", metavar="PORT")
    parser.add_option("-d", "--dst", dest="destip", default=None,
                      help="Destination ip", metavar="IP")
    parser.add_option("--proto", dest="proto", type="int", default=132,
                      help="Protocol number, default for sctp: 132", metavar="PROTOCOL")
    parser.add_option("-c", "--chunk", dest="chunk",default=None, help="Chunk payload",
                      metavar="DATA")

    options, args = parser.parse_args()
    if not options.destip:
        raise OptionValueError("'-d / --dst' for destination IP/Addr must be provided")
    destip = options.destip
    proto =options.proto
    srcport = int(options.src)
    dstport = int(options.dst)
    payload = options.chunk

    send_packet(destip=destip, dstport=dstport, srcport=srcport, proto=proto, payload=payload)
