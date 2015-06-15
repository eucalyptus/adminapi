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
    sock = None
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, 132)
    sock.bind((HOST, PORT))
    while True:
        data, (ip, info) = sock.recvfrom(1024)
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
    if sock:
        sock.close()
    raise
if sock:
    sock.close()
