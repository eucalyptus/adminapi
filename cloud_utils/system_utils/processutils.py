import subprocess
from multiprocessing import Process
from sys import stderr
from cloud_utils.log_utils import red, get_traceback, format_log_level, \
    get_logger_method_for_level, markup, TextStyle
import os
import re
import signal
from types import BuiltinFunctionType
import platform
from select import select
import traceback
import threading
import time



def local_cmd(cmd, verbose=True, timeout=120, inactivity_timeout=None,
              listformat=True, code=None, logger=None,
              log_level='DEBUG', shell=False, stdout_cb=None, stderr_cb=None, chunk_size=4096):
    """
           Run a command on the localhost
           :param cmd: str representing the command to be run
           :print_method: method used to print errors/output. ie:'logger.warn' Default is print().
           :return: :raise: CalledProcessError on non-zero return code
           """
    if not shell and re.search('[;&|]', cmd):
        warning = 'Cmd:"{0}". Compound commands require "shell" flag\n'.format(cmd)
        raise ValueError(warning)
    if not shell:
        args = cmd.split()
    else:
        args = cmd
    process = None
    retcode = None
    output = None
    inactivity_timeout = inactivity_timeout or timeout
    fd = None
    ret_dict = {'cmd': cmd,
                'stdout': None,
                'stderr': None,
                'rx_bytes': 0,
                'timeout': timeout,
                'inactivity_timeout': inactivity_timeout,
                'process': None,
                'pid': None,
                'run_error': None,
                'timeout_error': None}
    start = time.time()
    try:
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   bufsize=4096, shell=shell)
        ret_dict['process'] = process
        ret_dict['pid'] = process.pid
        process.cmd = cmd
        ret_dict.update(monitor_subprocess_io(process, listformat=listformat, verbose=verbose,
                                              chunk_size=chunk_size, logger=logger,
                                              log_level=log_level, timeout=timeout,
                                              inactivity_timeout=inactivity_timeout,
                                              stdout_callback=stdout_cb,
                                              stderr_callback=stderr_cb))
        if ret_dict['timeout_error']:
            os.kill(process.pid, signal.SIGINT)
            timeout = 0
        elapsed = time.time() - start
        while (not timeout or elapsed <= timeout) and process.poll() is None:
            elapsed = time.time() - start
            wait_timeout = timeout - elapsed
            if wait_timeout <= 0:
                wait_timeout = 1
            if process.poll() is not None:
                output, unused_err = process.communicate()
    finally:
        elapsed = time.time() - start
        if process:
            try:
                for fd in [process.stdin, process.stdout, process.stderr]:
                    if fd:
                        fd.close()
                    fd = None
            except Exception as FDE:
                stderr.write('{0}\nCmd:{1}, err closing fd:"{2}". err:"{3}"'
                            .format(get_traceback(), cmd, fd, FDE))
                stderr.flush()
            if process.returncode is None:
                try:
                    os.kill(process.pid, signal.SIGINT)
                    process.terminate()
                except Exception as E:
                    stderr.write('{0}\nCmd:{1}, err attempting to terminate. err:"{2}"'
                                 .format(get_traceback(), cmd, E))
                    stderr.flush()
                if not process.returncode:
                    process.returncode = -69
            ret_dict['status'] = process.returncode
            ret_dict['elapsed'] = elapsed

    process = None
    if code is not None and ret_dict['status'] != code:
        error = ProcessCodeError(ret_dict['status'], cmd, expected_code=code)
        if ret_dict['stderr']:
            error.output = ret_dict['stderr']
        raise error
    return ret_dict

def monitor_subprocess_io(process,
                          cmdstring=None,
                          logger=None,
                          log_level='DEBUG',
                          verbose=True,
                          chunk_size=4096,
                          stdout_callback=None,
                          stderr_callback=None,
                          status_queue=None,
                          status_interval=10,
                          listformat=False,
                          inactivity_timeout=None,
                          timeout=120):
    '''
    Monitors the io availability of the subprocess. Reads from stdout and stderr. 
    An optional destination callback can be provided to handle output for either stdout and/or
    stderr as data is received. The output of the callback will be appended to the returned 
    dictionary stdout or stderr attributes. 
    If there is no activity on stdout and stderr for a period of
    'inactivity_timeout' seconds than an error is raised. 
    If a logger is provided, stdout and stderr will be logged at the log level provided. 
    Upon completion a dict with information about the monitoring operation is returned:
        {'cb_result': int (if a provided call back returns a result per flush() otherwise None),
         'io_bytes': int (number of bytes read in),
         'stderr': str or list of strings depending on listformat flag,
         'stdout': str or list of strings depending on listformat flag,
         'timeout_error': Exception obj if either of the provided timeouts is exceeded, else None}
    :param process: subprocess obj
    :param cmdstring: optional str representing the command used for the process being monitored. 
    :param logger: optional logger obj used for logging debugging type messages at the log_level
                   provided. 
    :param log_level: log level used to select which method from the provided logger obj to use 
                      when writing debugging type messages from this monitor operation
    :param verbose: bool. If set will log the debugging output for this process. 
    :param chunk_size: if using verbose, this is the max size to be read-in (w/o a newline char) 
                       before writing debug output. 
    :param stdout_callback: A call back or file like obj to be used to handle stdout data as it 
                           is read in. See "ProcessOutputCallBack" for more info. 
    :param stderr_callback: A call back or file like obj to be used to handle stderr data as it 
                           is read in. See "ProcessOutputCallBack" for more info.
    :param listformat: bool. If set will return stdout/stderr as a lists instead of single buffers
    :param inactivity_timeout: int seconds to allow for no infile
                               activity before raising error. Use 0 for no timeout. 
    :param timeout: General overall timeout for this operation. Use 0 for no timeout. 
    returns dict (see above)
    '''
    cmdstring = cmdstring or getattr(process, 'cmd', None)
    assert isinstance(process, subprocess.Popen), "Process must be of type:{0}, got:{1}/{2}"\
        .format(subprocess.Popen, process, type(process))
    inactivity_timeout = inactivity_timeout or timeout
    sub_stdout = process.stdout
    sub_stdout_fd = sub_stdout.fileno()
    sub_stderr = process.stderr
    sub_stderr_fd = sub_stderr.fileno()
    timeout = timeout or None
    inactivity_timeout = inactivity_timeout or timeout
    _orig_inactivity_timeout = inactivity_timeout
    fd_mon = {}
    fd_mon[sub_stdout_fd] = {'buf': "", 'last_read': None, 'cb': stdout_callback,
                             'name': 'stdout', 'fileobj': sub_stdout,
                             'cb_data': {'process': process}}
    fd_mon[sub_stderr_fd] = {'buf': "", 'last_read': None, 'cb': stderr_callback,
                             'name': 'stderr', 'fileobj': sub_stderr,
                             'cb_data': {'process': process}}

    ret_dict = {'stdout': "",
                'stderr': "",
                'io_bytes': 0,
                'cb_result': None,
                'timeout_error': None}
    if logger:
        log_level = format_log_level(log_level)
        log_method = get_logger_method_for_level(level=log_level, logger=logger)
    else:
        def log_method(msg):
            print msg
    if cmdstring:
        try:
            hostname = platform.uname()[1]
        except:
            hostname = "LOCAL"
        log_method("({0}):{1}#: {2}".format(process.pid, hostname, cmdstring.strip('\n')))

    last_read = time.time()

    def show_output(fd, force_flush=False):
        if not verbose:
            return
        show_n_flush_buf = force_flush
        if fd_mon[fd]['buf'] and fd_mon[fd]['buf'][-1] == "\n":
            show_n_flush_buf = True
        if len(fd_mon[fd]['buf']) >= chunk_size:
            print ''
            show_n_flush_buf = True
        if fd_mon[fd]['last_read'] is None:
            fd_mon[fd]['last_read'] = last_read
        if show_n_flush_buf:
            prefix = "({0}): ".format(process.pid)
            if  fd_mon[fd]['name'] == 'stderr':
                log_method(red("{0}{1}".format(prefix, fd_mon[fd]['buf'].strip('\n'))))
            else:
                log_method("{0}{1}".format(prefix, fd_mon[fd]['buf'].strip('\n')))
            fd_mon[fd]['buf'] = ""
            fd_mon[fd]['last_read'] = last_read

    try:
        # Set additional infile timer using 'last_read', in case
        # other fds are monitored as well such as stdout,stderr
        done = False
        start = time.time()
        read_fds = fd_mon.keys()
        while not done and read_fds:
            elapsed = time.time() - start
            if timeout is not None and (elapsed > timeout):
                raise RuntimeError('({0}) Timed Out after:{1} seconds monitoring process'
                                   .format(process.pid, timeout))
            if timeout is not None and (inactivity_timeout > (timeout - elapsed)):
                inactivity_timeout = (timeout - elapsed)
            # Make sure inactivity timeout is > 0, or None here.
            reads, writes, errors = select(read_fds, [], [],
                                           inactivity_timeout)
            if len(reads) > 0:
                for fd in reads:
                    if fd in fd_mon.keys():
                        # check for each fds in read ready list
                        last_read = time.time()
                        fileobj = fd_mon[fd]['fileobj']
                        if fileobj.closed:
                            chunk = None
                        else:
                            chunk = fileobj.read(1)
                        if chunk:
                            fd_mon[fd]['buf'] += chunk
                            show_output(fd)
                            if fd_mon[fd]['cb']:
                                # Feed provided callback data read from FD along with the
                                # CB data dict...
                                cb_data = fd_mon[fd]['cb_data']
                                cb_data['timeout'] = timeout
                                cb_data['inactivity_timeout'] = inactivity_timeout
                                cb_data['fd'] = fd
                                cb_data['elapsed'] = elapsed
                                cb_data['last_read'] = fd_mon[fd]['last_read']
                                # Allow for CB or file like obj...
                                if isinstance(fd_mon[fd]['cb'].write, BuiltinFunctionType):
                                    cb_data = fd_mon[fd]['cb'].write(chunk)
                                else:
                                    cb_data = fd_mon[fd]['cb'].write(chunk, data=cb_data)
                                # cb can change the read in data as well as timeout values.
                                # remove values from cb_data after reading to return to cb on
                                # next fd read iteration...
                                if cb_data is not None:
                                    if 'buf' in cb_data:
                                        chunk = cb_data.pop('buf')
                                    if 'timeout' in cb_data:
                                        timeout = cb_data.pop('timeout')
                                    if 'inactivity_timeout' in cb_data:
                                        inactivity_timeout = cb_data.pop('inactivity_timeout')
                                # Allow the CB to provide itself with data on the next
                                # iteration in the cb_data...
                                fd_mon[fd]['cb_data'] = cb_data
                            ret_dict[fd_mon[fd]['name']] += chunk
                            ret_dict['io_bytes'] += len(chunk)
                        else:
                            read_fds.remove(fd)
                            if fd_mon[fd]['cb']:
                                # Allow for CB or file like obj...
                                if isinstance(fd_mon[fd]['cb'].flush, BuiltinFunctionType):
                                    ret_dict['cb_result'] = fd_mon[fd]['cb'].flush()
                                else:
                                    ret_dict['cb_result'] = \
                                        fd_mon[fd]['cb'].flush(data=fd_mon[fd]['cb_data'])
                    else:
                        log_method('({0}) None of the readfds have appeared in the read ready list '
                                   'for the inactivity period:"{1}"'.format(process.pid,
                                                                            inactivity_timeout))
                        read_elapsed = int(time.time() - last_read)
                        if inactivity_timeout and read_elapsed > inactivity_timeout:
                            raise ProcessTimeoutError(pid=process.pid, elapsed=read_elapsed,
                                                      cmd=cmdstring, timeout=timeout,
                                                      inactivity_timeout=_orig_inactivity_timeout)
                        done = True
            else:

                error = ('({0}) Cmd:"{1}", Monitor process activity timeout fired after {2} seconds. '
                         'Inactivity_timeout:{3}, General Timeout:{4}'
                         .format(process.pid, cmdstring or "unknown",
                                 "{0:.2f}".format(float(inactivity_timeout)),
                                 _orig_inactivity_timeout, timeout))
                log_method(error)
                if not inactivity_timeout:
                    error += "({0}) Check process monitor code. Inactivity timeout was not " \
                             "set and should not get here?".format(process.pid)
                raise ProcessTimeoutError(pid=process.pid, cmd=cmdstring, timeout=timeout,
                                          elapsed=inactivity_timeout,
                                          inactivity_timeout=_orig_inactivity_timeout)
    except ProcessTimeoutError as PE:
        ret_dict['timeout_error'] = PE
    finally:
        try:
            for fd in fd_mon.iterkeys():
                if fd_mon[fd]['buf']:
                    show_output(fd, force_flush=True)
                    if fd_mon[fd]['cb']:
                        # Allow for CB or file like obj...
                        if isinstance(fd_mon[fd]['cb'].flush, BuiltinFunctionType):
                            ret_dict['cb_result'] = fd_mon[fd]['cb'].flush()
                        else:
                            ret_dict['cb_result'] = \
                                fd_mon[fd]['cb'].flush(data=fd_mon[fd]['cb_data'])
        finally:
            log_method('\n({0}) Monitor subprocess io finished\n'.format(process.pid))
        if listformat:
            for fd in fd_mon.iterkeys():
                ret_dict[fd_mon[fd]['name']] = ret_dict[fd_mon[fd]['name']].splitlines()
    return ret_dict


def close_all_fds(except_fds=None):
    '''
    Closes all fds outside of stdout,stderr for this process/subprocess.
    :param except_fds: list of files, or fds to 'not' close
    '''
    except_filenos = [1, 2]
    if except_fds is not None:
        for except_fd in except_fds:
            if except_fd is None:
                pass
            elif isinstance(except_fd, int):
                except_filenos.append(except_fd)
            elif hasattr(except_fd, 'fileno'):
                except_filenos.append(except_fd.fileno())
            else:
                raise ValueError('{0} must be an int or have a fileno method'
                                 .format(repr(except_fd)))

    fileno_ranges = []
    next_range_min = 0
    for except_fileno in sorted(except_filenos):
        if except_fileno > next_range_min:
            fileno_ranges.append((next_range_min, except_fileno))
        next_range_min = max(next_range_min, except_fileno + 1)
    fileno_ranges.append((next_range_min, 1024))

    for fileno_range in fileno_ranges:
        os.closerange(fileno_range[0], fileno_range[1])

def open_pipe_fileobjs():
    '''
    helper method to create and return pipe file like objs
    :returns read_pipe_file, write_pipe_file
    '''
    pipe_r, pipe_w = os.pipe()
    return os.fdopen(pipe_r), os.fdopen(pipe_w, 'w')


def spawn_process(func, **kwargs):
    p = Process(target=process_wrapper, args=[func], kwargs=kwargs)
    p.start()
    return p


def process_wrapper(func, **kwargs):
    name = getattr(func, '__name__', 'unknown')
    try:
        func(**kwargs)
    except KeyboardInterrupt:
        pass
    except Exception, e:
        traceback.print_exc()
        msg = 'Error in wrapped process {0}:{1}'.format(str(name), str(e))
        print >> os.sys.stderr, msg
        return
    os._exit(os.EX_OK)


def pid_exists(pid):
    '''
    Helper method to send a kill 0 signal to poll if pid is alive
    :returns boolean, true if pid is found, false if not.
    '''
    try:
        #Check to see if pid exists
        os.kill(pid, 0)
        return True
    except OSError, ose:
        if ose.errno == os.errno.ESRCH:
            #Pid was not found
            return False
        else:
            raise ose


def check_and_waitpid(pid, status):
    if pid_exists(pid):
        try:
            os.waitpid(pid, status)
        except OSError:
            pass


def wait_process_in_thread(pid):
    """
    Start a thread that calls os.waitpid on a particular PID to prevent
    zombie processes from hanging around after they have finished.
    """
    if pid and pid_exists(pid):
        pid_thread = threading.Thread(target=check_and_waitpid, args=(pid, 0))
        pid_thread.daemon = True
        pid_thread.start()
        return pid_thread


# Exception classes used by this module.
class ProcessCodeError(subprocess.CalledProcessError):

    def __init__(self, returncode, cmd, output=None, expected_code=None):
        self.expected_code = expected_code
        super(ProcessCodeError, self).__init__(returncode=returncode, cmd=cmd, output=output
                                               )
    def __str__(self):
        msg = ('Cmd: "{0}" exit code:"{1}" != expected status:"{2}". '
               .format(self.cmd, self.returncode, self.expected_code))
        if self.output:
            msg += 'Output:"{0}"'.format(self.output)
        return msg

# Exception classes used by this module.
class ProcessTimeoutError(Exception):

    def __init__(self, pid, elapsed, timeout, cmd=None, inactivity_timeout=None):
        self.pid = pid
        self.elapsed = "{0:.2f}".format(float(elapsed))
        self.cmd = cmd
        self.timeout = "{0:.2f}".format(float(timeout))

        if inactivity_timeout is not None:
            inactivity_timeout = "{0:.2f}".format(float(inactivity_timeout))
        self.inactivity_timeout = inactivity_timeout

    def __str__(self):
        msg = "({0})".format(self.pid)
        if self.cmd:
            msg = '{0}: Command:"{1}", '.format(msg, self.cmd)
        msg += 'excution timeout. Elapsed:{0}, general timeout:{1}, inactivity_timeout:{2}'\
            .format(self.elapsed, self. timeout, self.inactivity_timeout)
        return msg




class ProcessOutputCallBack(object):
    """
    Base Call back for use when monitoring process stdout/stderr FDs. 
    """

    def __init__(self):
        self.cb_data = {}
        self.return_code = None
        pass

    def write(self, buf, data=None):
        """
        This method is intended to handle the latest buffer read from process being monitored. 
        Actions can be taking on the provided buffer and manipulated when returned to the 
        monitor function by storing in the 'buf' attribute of the cb_data dict to be returned. 
        Data in the cb_data dict can be used to manipulate the timeouts of the 
        process monitor, and/or be used to persist data across multiple write()s. 
        :param buf: buffer read from process
        :param data: data dict with information about process, fd, timeouts, etc.. 
        :return: data_dict
        """
        return self.cb_data

    def flush(self, data=None):
        """
        Indicates the monitoring process is done reading from the process and flushing. 
        :param data: cb_data dict used to store information about this specific process fd's 
        monitoring. A return code can be provided here to indicate the desired return code
        for the call back. If not 'None' this will be used to override the underlying process's 
        return code 
        :return:  int 
        """
        return self.return_code


class TestOutputCallback(ProcessOutputCallBack):
    """
    Sample process output callback. 
    """

    def __init__(self):
        self.local_buf = ""
        self.line_cnt = 0

    def print_debug(self, msg):
        print markup(msg, markups=[TextStyle.INVERSE, TextStyle.BOLD])

    def store_until_newline(self, buf):
        lines = []
        for c in buf or "":
            if c == "\n":
                lines.append(self.local_buf)
                self.local_buf = ""
            else:
                self.local_buf += c
        return lines

    def write(self, buf, data=None):
        elapsed = None
        if not data.get('cb_bytes_read', None):
            self.print_debug('CallBack Dict:"{0}"'.format(data))
            data['cb_bytes_read'] = len(buf)
        else:
            data['cb_bytes_read'] += len(buf)
        data['buf'] = ""
        for line in self.store_until_newline(buf):
            data['buf'] += 'Got a line:{0}\n'.format(line)
            self.line_cnt += 1
        if data['buf']:
            now = round(time.time(), 3)
            last_line_read = data.get('cb_last_read', None)
            if last_line_read is None:
                if data.get('elapsed', None) is not None:
                    elapsed = data['elapsed']
            if elapsed is None:
                elapsed = now - last_line_read
            elapsed ="{0:.3f}".format(elapsed)
            data['cb_last_read'] = now
            self.print_debug('Callback read line#"{0}", elapsed since last line:"{1}"'
                             .format(self.line_cnt, elapsed))
        return data

    def flush(self, data=None):
        return_code = -999
        self.print_debug('Flushing test callback, returning code: {0}'.format(return_code))
        return return_code




