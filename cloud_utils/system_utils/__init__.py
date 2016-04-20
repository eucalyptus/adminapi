import subprocess
from sys import stderr
from cloud_utils.log_utils import red



def local(cmd, print_method=None):
        """
        Run a command on the localhost
        :param cmd: str representing the command to be run
        :print_method: method used to print errors/output. ie:'logger.warn' Default is print().
        :return: :raise: CalledProcessError on non-zero return code
        """

        def print_debug(msg):
            msg = red(msg)
            if print_method:
                print_method(msg)
            else:
                stderr.write("{0}\n".format(msg))
                stderr.flush()
        args = cmd.split()
        process = None
        retcode = None
        output = None
        try:
            process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       bufsize=4096)
            output, unused_err = process.communicate()
            retcode = process.poll()
        finally:
            if process:
                try:
                    for fd in [process.stdin, process.stdout, process.stderr]:
                        if fd:
                            fd.close()
                except Exception as FDE:
                    print_debug('local:{0}, err closing fd:"{1}". err:"{2}"'
                                     .format(cmd, fd, FDE))
        if retcode:
            error = subprocess.CalledProcessError(retcode, cmd)
            error.output = output
            raise error
        return output.split("\n")

