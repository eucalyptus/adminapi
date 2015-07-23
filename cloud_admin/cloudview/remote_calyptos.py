#!/usr/bin/python

from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter, ArgumentError
import os
import re
import sys
import time
from traceback import print_exc
try:
    from cloud_utils.net_utils.sshconnection import SshConnection, CommandExitCodeException, \
        SshCbReturn
    from cloud_utils.log_utils.eulogger import Eulogger
    from cloud_utils.log_utils import markup
except ImportError as IE:
    sys.stderr.write("Import adminapi error, missing adminapi? Try:\n"
                     "git clone https://github.com/bigschwan/adminapi.git; cd adminapi; "
                     "python setup.py install\n")
    sys.stderr.flush()
    raise IE


parser = ArgumentParser(description='Utility for installing and running Calyptos on a '
                                    'remote machine.',
                        usage='remote_calyptos <host ip> <options>',
                        formatter_class=ArgumentDefaultsHelpFormatter)

parser.add_argument("--debug", action="store_true", default=False,
                    help="increase output verbosity")
parser.add_argument("host", default=None,
                    help="Primary Host to install and run Calyptos from")
parser.add_argument("-l", "--local-env", default=None,
                    help="A local path to the Calyptos environment.yml file used to "
                         " describe the topology being built")
parser.add_argument("-e", "--env", default=None,
                    help="A remote path to the Calyptos environment.yml file used to "
                         " describe the topology being built. Must be an absolute path"
                         "or one relative to the Calyptos source dir."
                         "By default will create 'environment.yml' in the calyptos source dir")
parser.add_argument("-c", "--config", default=None,
                    help="A local or remote path to the Calyptos configuration file. Used for"
                         "Calyptos internal mappings")
parser.add_argument("-p", "--password", default=None,
                    help="Password for ssh connection to remote Calyptos host")
parser.add_argument("--calyptos_password", default=None,
                    help="Password for ssh connection from Calyptos host to remaining hosts in"
                         "the topology")
parser.add_argument("-u", "--username", default='root',
                    help="Username for Calyptos host ssh connection")
parser.add_argument("-i", "--install_timeout", default=600, type=int,
                    help="Timeout used installation operations on remote host")
parser.add_argument("-t", "--timeout", default=600, type=int,
                    help="Inactivity timeout used for run time operations, ie when executing Calyptos "
                         "commands on the remote host. Timeout is restored whenver the remote"
                         "operation returns output to stdout or stderr")
parser.add_argument("-r", "--repo", default="https://github.com/eucalyptus/calyptos",
                    help="Calyptos repo url")
parser.add_argument("--packages", default="python-devel, gcc, git, python-setuptools, "
                                          "fabric, PyYAML, python-stevedore, python-virtualenv",
                    help="Comma separated list of linux packages to install")
parser.add_argument("-v", "--virtualenv", default=None,
                    help="Calyptos virtual env, default value of 'None' will "
                         "install outside a virtualenv")
parser.add_argument("-d", "--destdir", default="",
                    help="Destination dir to install Calyptos source and virtualenv, default "
                         "is in the home dir of the ssh login user")
parser.add_argument("--venv-args", dest='venv_args', default="",
                    help="String to be appended to virtualenv active command contain cli args")
parser.add_argument("-b", "--branch", default="master",
                    help="Branch to be used for Calyptos")
parser.add_argument("--commands", default="prepare, bootstrap, provision",
                    help="Comma separated list of Calyptos commands to run on remote system")




args = parser.parse_args()
if not args.host:
    raise ArgumentError(args.host, 'Remote host (ip/hostname) must be provided')
log_level = 'info'
if args.debug:
    log_level = 'debug'
logger = Eulogger(stdout_level=log_level, identifier=args.host)
venv_dest = None
if args.virtualenv:
    venv_dest = os.path.join(args.destdir, args.virtualenv)
ssh = SshConnection(host=args.host, password=args.password, username=args.username,
                    logger=logger, verbose=args.debug)

def remote_sys(cmd, code=0, timeout=60, list_format=True, verbose=args.debug,
        enable_debug=args.debug):
    return ssh.sys(cmd, code=code, timeout=timeout, listformat=list_format, verbose=verbose)
    

def install_linux_rpms(packages=None):
    """
    Check for an existing install, if not found attempt to install it.
    :param packages: list of packages or string w/ comma separated list of packages
    """
    remove = []
    packages = packages or args.packages
    if not isinstance(packages, list):
        packages = str(packages).split(",")
    rpms = remote_sys('rpm -qa', code=0, timeout=30)
    for rpm in rpms:
        if not rpm:
            continue
        for pkg in packages:
            if re.search("^{0}-".format(pkg.strip()), rpm):
                logger.debug('Found matching pkg:{0} in rpm:{1}'.format(pkg, rpm))
                remove.append(pkg)
    for package in remove:
        if package in packages:
            packages.remove(package)
    packages = " ".join(packages)
    if packages:
        remote_sys('yum install -y --nogpg {0}'.format(packages), code=0,
                   timeout=args.install_timeout)


def setup_virtual_env(dest=None):
    dest = dest or venv_dest
    if not dest:
        logger.info('Virtual env info not provided so not using a virtual env')
        return None
    remote_sys('virtualenv {0}'.format(dest), code=0, timeout=30)
    return dest

def prepare_calyptos_source(destdir=None, branch=None, repo=None, virtualenv=None):
    remote = None
    repo = repo or args.repo
    venv = virtualenv or venv_dest
    dest = 'calyptos'
    destdir = destdir or args.destdir
    branch = branch or args.branch
    if destdir:
        dest = os.path.join(destdir, 'calyptos')
    git_prefix = 'cd {0} && git '.format(dest)

    def git(cmd, code=0, timeout=60):
        return remote_sys(git_prefix + str(cmd), code=code, timeout=timeout)

    try:
        # Check if there is a local git checkout already at dest...
        git_dir = os.path.join(dest, '.git')
        remote_sys('ls {0}'.format(git_dir), code=0)
        # A directory was found, now make sure its up to date and using the given repo/branch...
        try:
            try:
                remote = git("remote -v | grep {0}".format(repo))[0]
                remote = remote.split()[0]
            except CommandExitCodeException:
                remote_name = "new"
                # Find the remote name for the provided repo, or add it...
                remotes = git("remote -v | awk '{print $1}'")
                for x in xrange(0, 10):
                    if remote_name in remotes:
                        remote_name += str(x)
                    else:
                        remote = remote_name
                        break
                if not remote:
                    raise ValueError('Could not find an available git remote repo name to add new, '
                                     'try cleaning remotes or adjusting this script')
            # Check to see if the local is up to date, if not pull from the remote...
            git('fetch {0}'.format(remote))
            git('checkout {0}'.format(branch))
            ssh.sys("cd {0} && [ $(git rev-parse {1}/{2}) == $(git rev-parse {1}) ] || "
                    "git pull {1} {2}".format(dest, remote, branch))
        except Exception as E:
            logger.critical('Failed to prepare Calyptos source bits on remote host!')
            print_exc(E)
            raise RuntimeError('Failed to prepare Calyptos source bits on remote host.\nError:\n'
                               + str(E))
    except CommandExitCodeException:
        # Calyptos bits are not present, clone em...
        remote_sys('git clone {0} -b {1} {2}'.format(repo, branch, dest), code=0)
    venv_prefix = ""
    # Finally make sure the proper bits are installed in the venv or globally if no venv...
    # Seems to be an error on exit when installing in a remote virtual env, may need to
    # debug further...
    if venv:
        logger.info('Got venv:{0}'.format(venv))
        venv_prefix = os.path.join(venv, 'bin/activate')
        venv_prefix = "source {0} && ".format(venv_prefix)
    remote_sys(venv_prefix + 'cd {0} && python setup.py install'.format(dest), code=0,
               timeout=args.install_timeout)

def setup(packages=None, venvdest=None, destdir=None, branch=None, repo=None):
    install_linux_rpms(packages=packages)
    # setup_virtual_env(dest=venvdest)
    prepare_calyptos_source(destdir=destdir, branch=branch, repo=repo, virtualenv=venv_dest)

def sync_environment_with_remote(local_path, remote_path):
    ssh.sftp_put(local_path, remote_path)


def update_output(buf):
    ret = SshCbReturn()
    logger.debug(buf)
    ret.settimer = args.timeout # Add  seconds back to timeout
    ret.buf = buf
    return ret

def prep_and_provision(local_env=None, remote_env=None, password=None, virtualenv=None,
                       destdir=None, commands=None):
    commands = commands or args.commands
    if not commands:
        logger.warn('No Calyptos commands were provided to be run on remote system')
        return
    if not isinstance(commands, list):
        commands = commands.split(",")
    password = args.calyptos_password or args.password
    if not password:
        raise ValueError('Need password for Calyptos Machines')
    venv = virtualenv or venv_dest
    dest = 'calyptos'
    destdir = destdir or args.destdir

    if destdir:
        dest = os.path.join(destdir, 'calyptos')
    # Prep the remote environment file...
    remote_env = remote_env or args.env
    local_env = local_env or args.local_env
    if not remote_env:
        remote_env = 'environment.yml'
        remote_env_dest = os.path.join(dest, remote_env)
    else:
        remote_env_dest = remote_env

    if local_env:
        sync_environment_with_remote(local_env, remote_env_dest)
    try:
        ssh.sys('ls {0}'.format(os.path.join(dest,remote_env)), code=0)
    except CommandExitCodeException:
        raise RuntimeError('Remote environment not found on:"{0}". '
                           'Use --env to point to an existing remote environment.yml or '
                           'transfer a local one with --local-env'
                           'Remote path:"{0}:'.format(ssh.host, remote_env))
    venv_prefix = "cd {0} && ".format(dest)
    if venv:
        logger.info('Got venv:{0}'.format(venv))
        venv_prefix = os.path.join(venv, 'bin/activate')
        venv_prefix = "source {0} && cd {1} && ".format(venv_prefix, dest)
    vpython = 'python'

    def run(command, cb=None):

        cmd = ("{0} calyptos --debug {1} -e {2} -p {3}"
               .format(venv_prefix, command, remote_env, password))
        logger.debug("\n######################################################################\n"
                     " STARTING {0}...\n"
                     " CMD: {1}\n"
                     " Running Calyptos frontend at:'{2}'\n"
                     "######################################################################\n"
                     .format(command.upper(), cmd, ssh.host))
        ssh.close()
        ssh.refresh_connection()
        time.sleep(1)
        out = ssh.cmd(cmd, timeout=args.timeout, cb=cb, verbose=args.debug)
        logger.debug("\n######################################################################\n"
                     " FINISHED {0}. EXIT CODE: {1}\n"
                     " CMD: {2}\n"
                     " Running Calyptos frontend at:'{3}'\n"
                     "######################################################################\n"
                     .format(command.upper(), out['status'], cmd, ssh.host))
        if out['status'] != 0:
            raise RuntimeError('Command:"{0}",  exited with non-zero status see log output '
                               'for more info'.format(cmd))
    # Finally iterate through the provided Calyptos commands and run them on the remote system.
    for command in commands:
        run(command)

setup()
prep_and_provision()

sys.exit(0)

