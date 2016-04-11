from cloud_utils.net_utils.sshconnection import SshConnection
from cloud_utils.log_utils import red, green, blue
from cloud_utils.log_utils.eulogger import Eulogger
from cloud_utils.log_utils import get_traceback
import argparse
from socket import inet_aton
import struct
import  time
from threading import Thread, Lock
from Queue import Queue, Empty
from prettytable import PrettyTable

class RemoteCommands(object):
    """
    Utility to run commands on remote machines via ssh in batches.
    """
    
    def __init__(self, hostfile=None, ips=None, password=None, username='root',
                 command='echo "ALIVE', timeout=5, thread_count=20, log_level='debug'):

        self.parser = argparse.ArgumentParser(
            description='Run a command on list of remote hosts',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        self.parser.add_argument('-f', '--hostfile', default=hostfile,
                            help='file with list of ips and/or hostnames')
        self.parser.add_argument('-i', '--ips', default=ips,
                            help='comma or space separated list of ips and/or hostnames')
        self.parser.add_argument('-p', '--password', default=password,
                            help='Ssh password used to connect to hosts')
        self.parser.add_argument('-u', '--username', default=username,
                            help='Ssh username used to connect to hosts')
        self.parser.add_argument('-c', '--command', default=command,
                            help='file with list of ips and/or hostnames')
        self.parser.add_argument('-t', '--timeout', default=timeout, type=int,
                            help='Ssh connection timeout in seconds')
        self.parser.add_argument('--thread-count', default=thread_count, type=int,
                            help='Number of threads used to run commands on hosts')
        self.parser.add_argument('-l', '--log_level', default=log_level,
                            help='Loglevel')
        self.args = self.parser.parse_args()
        self.hostfile = self.args.hostfile
        self.password = self.args.password
        self.username = self.args.username
        self.command = self.args.command
        self.results = {}
        self.maxwait = .5
        self.ips = self.args.ips
        self.logger = Eulogger('RemoteCmds', stdout_level=self.args.log_level)
        if self.ips:
            self.ips = str(self.ips).replace(',', ' ')
            self.ips = self.ips.split()
        if self.args.hostfile:
            with open(hostfile) as f:
                self.ips.extend(f.readlines())
        if not self.ips:
            raise ValueError('No hosts provided. Use --hostfile or --ips to provide hosts to run '
                             'command against')

    def do_ssh(self, q, lock, name, command):
        try:
            self._do_ssh(q, lock, name, command)
        except Exception as SE:
            q.task_done()
            self.logger.error('{0}\nError in do_ssh:{0}'.format(get_traceback(), SE))

    def _do_ssh(self, q, lock, name, command):
        empty = False
        while not empty:
            ssh = None
            logger = None
            self.logger.debug('Thread: {0}, in Q loop...'.format(name))
            host = None
            try:
                host = q.get(timeout=self.maxwait)
            except Empty:
                empty = True
                break
            start = time.time()
            try:
                self.logger.debug('Connecting to new host:' + str(host))
                logger = Eulogger(str(host))
                ssh = SshConnection(host=host, username=self.username, password=self.password,
                                    debug_connect=True, timeout=self.args.timeout, verbose=True,
                                    logger=logger)
                logger.debug('host: {0} running command:{1} '.format(host, command))
                out = ssh.cmd(str(command), listformat=True)
                logger.debug('Done with host: {0}'.format(host))
                elapsed = int(time.time() - start)
                with lock:
                    self.results[host] = {'status': out.get('status'), 'output': out.get('output'),
                                     'elapsed': elapsed}
            except Exception as E:
                elapsed = int(time.time() - start)
                with lock:
                    self.results[host] = {'status': -1, 'output': str(E),
                                     'elapsed': elapsed}
            finally:
                logger.debug('Closing ssh to host: {0}'.format(host))
                if ssh:
                    ssh.connection.close()
                try:
                    if logger:
                        logger.close()
                except:
                    pass
                q.task_done()
                logger.debug('Closed ssh to host: {0}'.format(host))
        self.logger.debug('{0}: Done with thread'.format(name))

    def run_remote_commands(self, ips=None, printme=True):
        iq = Queue()
        ips = ips or self.ips
        if not ips:
            raise ValueError('run_remote_commands: IP list was empty:"{0}"'.format(ips))
        for ip in ips:
            ip = str(ip).strip().rstrip()
            iq.put(ip)
        tlock = Lock()
        threadcount = self.args.thread_count or 1
        self.results = {}
        for i in range(threadcount):
             t = Thread(target=self.do_ssh, args=(iq, tlock, i, self.command))
             t.daemon = True
             t.start()
        self.logger.debug('Threads started now waiting for join')
        iq.join()
        self.logger.debug('Done with join')
        time.sleep(self.maxwait + .1)
        return self.results

    def show_results(self, results=None, printmethod=None):
        results = results or self.results
        pt = PrettyTable(['HOST', 'RES', 'TIME', 'OUTPUT'])
        pt.align = 'l'
        pt.hrules = 1
        pt.padding_width = 0
        max = 80
        pt.max_width['OUTPUT'] = max
        for host in sorted(results, key=lambda ip: struct.unpack("!L", inet_aton(ip))[0]):
            result = self.results.get(host)
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
        buf = "\n{0}\n".format(pt)
        if printmethod:
            printmethod(buf)
        else:
            print buf


if __name__ == "__main__":
    rm = RemoteCommands()
    rm.run_remote_commands()
    rm.show_results()

