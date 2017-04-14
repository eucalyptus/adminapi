import subprocess
from multiprocessing import Process
from sys import stderr
from cloud_utils.log_utils import red, get_traceback
import os
import re
import sys
from select import select
import traceback
import threading
import time
from cloud_utils.log_utils import format_log_level, get_logger_method_for_level



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
                'io_bytes': 0,
                'timeout': timeout,
                'process': None}
    start = time.time()
    try:
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   bufsize=4096, shell=shell)
        ret_dict['process'] = process

        ret_dict.update(monitor_subprocess_io(process, listformat=listformat, verbose=verbose,
                                              chunk_size=chunk_size, logger=logger,
                                              log_level=log_level, timeout=timeout,
                                              inactivity_timeout=inactivity_timeout,
                                              stdout_callback=stdout_cb,
                                              stderr_callback=stderr_cb))
        elapsed = time.time() - start
        while elapsed <= timeout and process.poll() is None:
            elapsed = time.time() - start
            wait_timeout = timeout - elapsed
            if wait_timeout <= 0:
                wait_timeout = 1
            output, unused_err = process.communicate(timeout=wait_timeout)
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
                    process.terminate()
                except Exception as E:
                    stderr.write('{0}\nCmd:{1}, err attempting to terminate. err:"{2}"'
                                 .format(get_traceback(), cmd, E))
                    stderr.flush()
            ret_dict['status'] = process.returncode
            ret_dict['elapsed'] = elapsed

    process = None
    if code is not None and ret_dict['status'] != code:
        error = CalledProcessCodeError(ret_dict['status'], cmd, expected_code=code)
        if ret_dict['stderr']:
            error.output = ret_dict['stderr']
        raise error
    return ret_dict

def monitor_subprocess_io(process,
                          chunk_size=4096,
                          logger=None,
                          log_level='DEBUG',
                          verbose=True,
                          stdout_callback=None,
                          stderr_callback=None,
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
    :param process: subprocess obj
    :param chunk_size: size to read/write per iteration
    :param inactivity_timeout: int seconds to allow for no infile
                               activity before raising error. Use 0 for no timeout. 
    returns bytes written
    '''
    assert isinstance(process, subprocess.Popen), "Process must be of type:{0}, got:{1}/{2}"\
        .format(subprocess.Popen, process, type(process))
    inactivity_timeout = inactivity_timeout or timeout
    chunk_size = chunk_size or 1
    sub_stdout = process.stdout
    sub_stdout_fd = sub_stdout.fileno()
    sub_stderr = process.stderr
    sub_stderr_fd = sub_stderr.fileno()
    inactivity_timeout = inactivity_timeout or timeout
    _orig_inactivity_timeout = inactivity_timeout
    fd_mon = {}
    fd_mon[sub_stdout_fd] = {'buf': "", 'last_read': None, 'cb': stdout_callback,
                             'name': 'stdout', 'fileobj': sub_stdout}
    fd_mon[sub_stderr_fd] = {'buf': "", 'last_read': None, 'cb': stderr_callback,
                             'name': 'stderr', 'fileobj': sub_stderr}

    ret_dict = {'stdout': "",
                'stderr': "",
                'io_bytes': 0,
                'cb_result': None}
    if logger:
        log_level = format_log_level(log_level)
        log_method = get_logger_method_for_level(level=log_level, logger=logger)
    else:
        def log_method(msg):
            print msg

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
            prefix = "({0}): ".format(fd_mon[fd]['name'])
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
            if elapsed > timeout:
                raise RuntimeError('Timed Out after:{0} seconds monitoring process'
                                   .format(timeout))
            if inactivity_timeout > (timeout - elapsed):
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
                                chunk = fd_mon[fd]['cb'].write(chunk)
                            ret_dict[fd_mon[fd]['name']] += chunk
                            ret_dict['io_bytes'] += len(chunk)
                        else:
                            read_fds.remove(fd)
                            if fd_mon[fd]['cb']:
                                ret_dict['cb_result'] = fd_mon[fd]['cb'].flush()
                    else:
                        log_method('None of the readfds have appeared in the read ready list '
                                   'for the inactivity period:"{0}"'.format(inactivity_timeout))
                        read_elapsed = int(time.time() - last_read)
                        if inactivity_timeout and read_elapsed > inactivity_timeout:
                            raise RuntimeError(
                                'io monitor: {0} seconds elapsed since'
                                ' last read.'.format(read_elapsed))
                        done = True
            else:
                error = ('Monitor process activity timeout fired after {0:.2} seconds. '
                         'Inactivity_timeout:{1}, General Timeout:{2}'
                         .format(float(inactivity_timeout), _orig_inactivity_timeout, timeout))
                log_method(error)
                if not inactivity_timeout:
                    error += "Check process monitor code. Inactivity timeout was not set and " \
                             "should not get here?"
                raise RuntimeError(error)
    finally:
        try:
            for fd in fd_mon.iterkeys():
                if fd_mon[fd]['buf']:
                    show_output(fd, force_flush=True)
        finally:
            log_method('Monitor subprocess io finished')
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
class CalledProcessCodeError(subprocess.CalledProcessError):
    """This exception is raised when a process run by check_call() or
    check_output() returns a non-zero exit status.
    The exit status will be stored in the returncode attribute;
    check_output() will also store the output in the output attribute.
    """
    def __init__(self, returncode, cmd, output=None, expected_code=None):
        self.expected_code = expected_code
        super(CalledProcessCodeError, self).__init__(returncode=returncode, cmd=cmd, output=output
                                                 )
    def __str__(self):
        msg = ('Cmd: "{0}" exit code:"{1}" != expected status:"{2}". '
               .format(self.cmd, self.returncode, self.expected_code))
        if self.output:
            msg += 'Output:"{0}"'.format(self.output)
        return msg


class ProcessCallBack(object):

    def __init__(self):
        pass

    def write(self, buf):
        return buf

    def flush(self):
        pass


