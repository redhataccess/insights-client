"""
Collect all the interesting data for analysis
"""
import os
import re
from subprocess import Popen, PIPE, STDOUT
import errno
import shlex
import json
import archive
import logging
import six
from tempfile import NamedTemporaryFile
from soscleaner import SOSCleaner
from utilities import determine_hostname, _expand_paths, write_file_with_text
from constants import InsightsConstants as constants

APP_NAME = constants.app_name
logger = logging.getLogger(APP_NAME)
SOSCLEANER_LOGGER = logging.getLogger('soscleaner')
SOSCLEANER_LOGGER.setLevel(logging.ERROR)


class DataCollector(object):
    """
    Run commands and collect files
    """

    def __init__(self):
        self._set_black_list()
        self.archive = archive.InsightsArchive()

    def _set_black_list(self):
        """
        Never run these commands
        """
        self.black_list = ["rm", "kill", "reboot", "shutdown"]

    def _mangle_command(self, command, name_max=255):
        """
        Mangle the command name, lifted from sos
        """
        mangledname = re.sub(r"^/(usr/|)(bin|sbin)/", "", command)
        mangledname = re.sub(r"[^\w\-\.\/]+", "_", mangledname)
        mangledname = re.sub(r"/", ".", mangledname).strip(" ._-")
        mangledname = mangledname[0:name_max]
        return mangledname

    def run_command_get_output(self,
                               command,
                               exclude=None,
                               filters=None,
                               nolog=False):
        """
        Execute a command through the system shell. First checks to see if the
        requested command is executable. Returns (returncode, stdout, 0)
        """
        cmd_env = os.environ
        # ensure consistent locale for collected command output
        cmd_env['LC_ALL'] = 'C'
        if not six.PY3:
            command = command.encode('utf-8', 'ignore')
        args = shlex.split(command)
        if set.intersection(set(args), set(self.black_list)):
            raise RuntimeError("Command Blacklist")
        try:
            if not nolog:
                logger.debug("Executing: %s", args)
            proc0 = Popen(args, shell=False, stdout=PIPE, stderr=STDOUT,
                          bufsize=-1, env=cmd_env, close_fds=True)
        except OSError as err:
            if err.errno == errno.ENOENT:
                logger.debug("Command %s not found", command)
                return {'cmd': self._mangle_command(command),
                        'status': 127,
                        'output': "Command not found"}
            else:
                raise err

        dirty = False

        if exclude is not None:
            pattern_file = NamedTemporaryFile()
            pattern_file.write("\n".join(exclude))
            pattern_file.flush()
            cmd = "/bin/grep -F -v -f %s" % pattern_file.name
            proc1 = Popen(shlex.split(cmd.encode("utf-8")),
                          stdin=proc0.stdout,
                          stdout=PIPE)
            proc0.stdout.close()
            if filters is None:
                stdout, stderr = proc1.communicate()
            proc0 = proc1
            dirty = True

        if filters is not None:
            pattern_file = NamedTemporaryFile()
            pattern_file.write("\n".join(filters))
            pattern_file.flush()
            cmd = "/bin/grep -F -f %s" % pattern_file.name
            proc2 = Popen(shlex.split(cmd.encode("utf-8")),
                          stdin=proc0.stdout,
                          stdout=PIPE)
            proc0.stdout.close()
            stdout, stderr = proc2.communicate()
            dirty = True

        if not dirty:
            stdout, stderr = proc0.communicate()

        # Required hack while we still pass shell=True to Popen; a Popen
        # call with shell=False for a non-existant binary will raise OSError.
        if proc0.returncode == 126 or proc0.returncode == 127:
            stdout = "Could not find cmd: %s" % command

        logger.debug("Status: %s", proc0.returncode)
        logger.debug("stderr: %s", stderr)

        return {
            'cmd': self._mangle_command(command),
            'status': proc0.returncode,
            'output': stdout.decode('utf-8', 'ignore')
        }

    def run_commands(self, conf):
        """
        Run through the list of commands and add them to the archive
        """
        logger.debug("Beginning to execute commands")
        dontrun = None
        commands = conf['commands']
        try:
            dontrun = conf['dontrun']
            logger.debug("Skip list: %s", dontrun)
            good_commands = []
            for command in commands:
                if command['command'] in dontrun:
                    logger.debug("Skipping %s", command['command'])
                else:
                    good_commands.append(command)
            commands = good_commands
        except KeyError:
            logger.debug("Could not find dont run list")

        for command in commands:
            if 'ethtool' in command['command']:
                # Get the ethtool flag
                flag = None
                try:
                    flag = command['command'].split('-')[1]
                except LookupError:
                    pass
                self._handle_ethtool(flag)
            elif 'hostname' in command['command']:
                self._handle_hostname(command['command'])
            elif 'modinfo' in command['command']:
                self._handle_modinfo()
            elif len(command['pattern']):
                cmd = command['command']
                filters = command['pattern']
                output = self.run_command_get_output(cmd, filters=filters)
                self.archive.add_command_output(output)
            else:
                self.archive.add_command_output(
                    self.run_command_get_output(command['command']))
        logger.debug("Commands complete")

    def _get_interfaces(self):
        """
        Get valid ethernet interfaces on the system
        """
        interfaces = {}
        output = self.run_command_get_output(
            "/sbin/ip -o link")["output"].splitlines()
        for line in output:
            match = re.match(
                '.*link/ether', line.decode('utf-8', 'ignore').strip())
            if match:
                iface = match.string.split(':')[1].lstrip()
                interfaces[iface] = True
        return interfaces

    def _handle_modinfo(self):
        """
        Helper to handle modinfo
        """
        for module in os.listdir("/sys/module"):
            response = self.run_command_get_output("modinfo " + module)
            if response['status'] is 0:
                self.archive.add_command_output(response)
            else:
                logger.debug("Module %s not loaded; skipping", module)

    def _handle_hostname(self, command):
        """
        Helper to attempt to get fqdn as hostname
        """
        self.archive.add_command_output({
            'cmd': self._mangle_command(command),
            'status': 0,
            'output': determine_hostname()
        })

    def _handle_ethtool(self, flag):
        """
        Helper to handle ethtool not supporting *
        """
        for interface in self._get_interfaces():
            if flag is not None:
                cmd = "/sbin/ethtool -" + flag + " " + interface
            else:
                cmd = "/sbin/ethtool " + interface
            self.archive.add_command_output(self.run_command_get_output(cmd))

    def copy_files(self, conf):
        """
        Run through the list of files and copy them
        """
        logger.debug("Beginning to copy files")
        delete = None
        files = conf['files']
        try:
            delete = conf['delete']
        except LookupError:
            pass

        for _file in files:
            if not delete or (delete and _file['file'] not in delete):
                if len(_file['pattern']) == 0:
                    self.archive.copy_file(_file['file'])
                else:
                    self.copy_file_with_pattern(_file['file'], _file['pattern'])
            else:
                logger.debug("Skipping %s", _file['file'])
        logger.debug("File copy complete")

    def write_branch_info(self, branch_info):
        """
        Write branch information to file
        """
        logger.debug("Writing branch information to workdir")
        full_path = self.archive.get_full_archive_path('/branch_info')
        write_file_with_text(full_path, json.dumps(branch_info))

    def _copy_file_with_pattern(self, path, patterns):
        """
        Copy file, selecting only lines we are interested in
        """
        full_path = self.archive.get_full_archive_path(path)
        if not os.path.isfile(path):
            logger.debug("File %s does not exist", path)
            return
        logger.debug("Copying %s to %s with filters %s", path, full_path, str(patterns))
        with NamedTemporaryFile() as pattern_file:
            pattern_file.write("\n".join(patterns))
            pattern_file.flush()
            cmd = "/bin/grep -F -f %s %s" % (pattern_file.name, path)
            output = Popen(
                shlex.split(cmd.encode("utf-8")), stdout=PIPE).communicate()[0]
            write_file_with_text(full_path, output)

    def copy_file_with_pattern(self, path, patterns):
        """
        Copy a single file or regex, creating the necessary directories
        But grepping for pattern(s)
        """
        if "*" in path:
            paths = _expand_paths(path)
            for path in paths:
                self._copy_file_with_pattern(path, patterns)
        else:
            self._copy_file_with_pattern(path, patterns)

    def done(self, config):
        """
        Do finalization stuff
        """
        if config.getboolean(APP_NAME, "obfuscate"):
            cleaner = SOSCleaner(quiet=True)
            clean_opts = CleanOptions(self.archive.tmp_dir, config)
            fresh = cleaner.clean_report(clean_opts, self.archive.archive_dir)
            return fresh[0]
        return self.archive.create_tar_file()


class CleanOptions(object):
    """
    Options for soscleaner
    """

    def __init__(self, tmp_dir, config):
        self.report_dir = tmp_dir
        self.domains = []
        self.files = []
        self.quiet = True
        self.keywords = [constants.default_conf_dir + 'keywords']
        if config.getboolean(APP_NAME, "obfuscate_hostname"):
            self.hostname_path = "insights_commands/hostname"
        else:
            self.hostname_path = None
