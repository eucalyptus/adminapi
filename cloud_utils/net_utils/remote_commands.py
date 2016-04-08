from cloud_utils.net_utils.sshconnection import SshConnection
from cloud_utils.log_utils import red, green, blue
from cloud_utils.log_utils.eulogger import Eulogger
import argparse
from socket import inet_aton
import struct
import  time
from threading import Thread, Lock
from Queue import Queue, Empty
from prettytable import PrettyTable

parser = argparse.ArgumentParser(description='Run a command on list of remote hosts',
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('-f', '--hostfile', default=None,
                    help='file with list of ips and/or hostnames')
parser.add_argument('-i', '--ips', default=None,
                    help='comma or space separated list of ips and/or hostnames')
parser.add_argument('-p', '--password', default=None,
                    help='Ssh password used to connect to hosts')
parser.add_argument('-u', '--username', default='root',
                    help='Ssh username used to connect to hosts. '
                                                             'Default:"root"')
parser.add_argument('-c', '--command', default='echo "ALIVE"',
                    help='file with list of ips and/or hostnames')
parser.add_argument('-t', '--timeout', default=5, type=int,
                    help='Ssh connection timeout in seconds: Default:30')
parser.add_argument('--thread-count', default=20, type=int,
                    help='Number of threads used to run commands on hosts')
args = parser.parse_args()
hostfile = args.hostfile
password = args.password
username = args.username
command = args.command
results = {}
maxwait = .5
ips = []
if args.ips:
    ips = str(ips).replace(',', ' ')
    ips = ips.split()
if args.hostfile:
    with open(hostfile) as f:
        ips.extend(f.readlines())
if not ips:
    raise ValueError('No hosts provided. Use --hostfile or --ips to provide hosts to run '
                     'command against')

def do_ssh(q, lock, name):
    empty = False
    while not empty:
        ssh = None
        logger = None
        print 'Thread: {0}, in Q loop...'.format(name)
        try:
            host = q.get(timeout=maxwait)
        except Empty:
            empty = True
            break
        start = time.time()
        try:
            print 'Connecting to new host:' + str(host)
            logger = Eulogger(str(host))
            ssh = SshConnection(host=host, username=username, password=password, debug_connect=True,
                            timeout=args.timeout, verbose=True, logger=logger)
            print 'host: {0} running command:{1} '.format(host, command)
            out = ssh.cmd(str(command), listformat=True)
            print 'Done with host: {0}'.format(host)
            elapsed = int(time.time() - start)
            with lock:
                results[host] = {'status': out.get('status'), 'output': out.get('output'),
                                 'elapsed': elapsed}
        except Exception as E:
            elapsed = int(time.time() - start)
            with lock:
                results[host] = {'status': -1, 'output': str(E),
                                 'elapsed': elapsed}
        finally:
            print 'Closing ssh to host: {0}'.format(host)
            if ssh:
                ssh.connection.close()
            try:
                if logger:
                    logger.close()
            except:
                pass
            q.task_done()
            print 'Closed ssh to host: {0}'.format(host)
    print '{0}: Done with thread'.format(name)

iq = Queue()
for ip in ips:
    ip = str(ip).strip().rstrip()
    iq.put(ip)
tlock = Lock()
threadcount = args.thread_count or 1
for i in range(threadcount):
     t = Thread(target=do_ssh, args=(iq, tlock, i,))
     t.daemon = True
     t.start()
print 'Threads started now waiting for join'
iq.join()
print 'Done with join'
time.sleep(maxwait + .1)
pt = PrettyTable(['HOST', 'RES', 'TIME', 'OUTPUT'])
pt.align = 'l'
pt.hrules = 1
pt.padding_width = 0
max = 80
pt.max_width['OUTPUT'] = max
for host in sorted(results, key=lambda ip: struct.unpack("!L", inet_aton(ip))[0]):
    result = results.get(host)
    output = ""
    for line in result.get('output'):
        output += "\n".join((line[0+i:max+i] for i in range(0, len(line), max)))
    status = result.get('status')
    if status == 0:
        color = green
    else:
        color = red
    pt.add_row([blue(host), color(result.get('status')), color(result.get('elapsed')),
                color(output)])
print "\n{0}\n".format(pt)


