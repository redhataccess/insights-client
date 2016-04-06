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
from utilities import determine_hostname, _expand_paths, write_file_with_text, generate_container_id
from constants import InsightsConstants as constants

APP_NAME = constants.app_name
logger = logging.getLogger(APP_NAME)
# python 2.7
SOSCLEANER_LOGGER = logging.getLogger('soscleaner')
SOSCLEANER_LOGGER.setLevel(logging.ERROR)
# python 2.6
SOSCLEANER_LOGGER = logging.getLogger('redhat_access_insights.soscleaner')
SOSCLEANER_LOGGER.setLevel(logging.ERROR)


class InsightsSpec(object):
    '''
    A spec loaded from the uploader.json
    '''
    def __init__(self, spec, exclude):
        # exclusions patterns for this spec
        self.exclude = exclude
        # pattern for spec collection
        self.pattern = spec['pattern']
        # absolute destination inside the archive for this spec
        self.archive_path = spec['archive_file_name']


class InsightsCommand(InsightsSpec):
    '''
    A command spec
    '''
    def __init__(self, spec, exclude, mountpoint):
        InsightsSpec.__init__(self, spec, exclude)
        # substitute mountpoint for collection
        self.command = spec['command'].format(CONTAINER_MOUNT_POINT=mountpoint)
        self.mangled_command = self._mangle_command(self.command)
        # have to re-mangle archive path in case there's a pre-command arg
        self.archive_path = os.path.join(
            os.path.dirname(self.archive_path), self.mangled_command)
        if not six.PY3:
            self.command = self.command.encode('utf-8', 'ignore')

    def _mangle_command(self, command, name_max=255):
        """
        Mangle the command name, lifted from sos
        """
        mangledname = re.sub(r"^/(usr/|)(bin|sbin)/", "", command)
        mangledname = re.sub(r"[^\w\-\.\/]+", "_", mangledname)
        mangledname = re.sub(r"/", ".", mangledname).strip(" ._-")
        mangledname = mangledname[0:name_max]
        return mangledname

    def get_output(self):
        '''
        Execute a command through system shell. First checks to see if
        the requested command is executable. Returns (returncode, stdout, 0)
        '''
        # ensure consistent locale for collected command output
        cmd_env = {'LC_ALL': 'C'}
        args = shlex.split(self.command)

        # never execute this stuff
        black_list = ['rm', 'kill', 'reboot', 'shutdown']
        if set.intersection(set(args), set(black_list)):
            raise RuntimeError("Command Blacklist")

        try:
            logger.debug('Executing: %s', args)
            proc0 = Popen(args, shell=False, stdout=PIPE, stderr=STDOUT,
                          bufsize=-1, env=cmd_env, close_fds=True)
        except OSError as err:
            if err.errno == errno.ENOENT:
                logger.debug('Command %s not found', command)
                return {'status': 127,
                        'output': 'Command not found'}
            else:
                raise err

        dirty = False

        cmd = "/bin/sed -rf " + constants.default_sed_file
        sedcmd = Popen(shlex.split(cmd.encode('utf-8')),
                       stdin=proc0.stdout,
                       stdout=PIPE)
        proc0.stdout.close()
        proc0 = sedcmd

        if self.exclude is not None:
            exclude_file = NamedTemporaryFile()
            exclude_file.write("\n".join(self.exclude))
            exclude_file.flush()
            cmd = "/bin/grep -F -v -f %s" % exclude_file.name
            proc1 = Popen(shlex.split(cmd.encode("utf-8")),
                          stdin=proc0.stdout,
                          stdout=PIPE)
            proc0.stdout.close()
            if self.pattern is None or len(self.pattern) == 0:
                stdout, stderr = proc1.communicate()
            proc0 = proc1
            dirty = True

        if self.pattern is not None and len(self.pattern):
            pattern_file = NamedTemporaryFile()
            pattern_file.write("\n".join(self.pattern))
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
            'status': proc0.returncode,
            'output': stdout.decode('utf-8', 'ignore')
        }


class InsightsFile(InsightsSpec):
    '''
    A file spec
    '''
    def __init__(self, spec, exclude, mountpoint):
        InsightsSpec.__init__(self, spec, exclude)
        # substitute mountpoint for collection
        self.real_path = spec['file'].format(CONTAINER_MOUNT_POINT=mountpoint)
        self.archive_path = self.archive_path.format(EXPANDED_FILE_NAME=spec['file'])

    def copy_files():
        '''
        Copy file into archive, selecting only lines we are interested in
        '''
        if not os.path.isfile(self.real_path):
            logger.debug('File %s does not exist' % self.real_path)
            return

        logger.debug('Copying %s to %s with filters %s' % (
            self.real_path, self.archive_path, str(self.pattern)))

        cmd.append("/bin/sed".encode('utf-8'))
        cmd.append("-rf".encode('utf-8'))
        cmd.append(constants.default_sed_file.encode('utf-8'))
        cmd.append(real_path.encode('utf8'))
        sedcmd = Popen(cmd,
                       stdout=PIPE)

        if exclude is not None:
            exclude_file = NamedTemporaryFile()
            exclude_file.write("\n".join(exclude))
            exclude_file.flush()

            cmd = "/bin/grep -v -F -f %s" % exclude_file.name
            args = shlex.split(cmd.encode("utf-8"))
            proc = Popen(args, stdin=sedcmd.stdout, stdout=PIPE)
            sedcmd.stdout.close()
            stdin = proc.stdout
            if patterns is None:
                output = proc.communicate()[0]
            else:
                sedcmd = proc

        if patterns is not None:
            pattern_file = NamedTemporaryFile()
            pattern_file.write("\n".join(patterns))
            pattern_file.flush()

            cmd = "/bin/grep -F -f %s" % pattern_file.name
            args = shlex.split(cmd.encode("utf-8"))
            proc1 = Popen(args, stdin=sedcmd.stdout, stdout=PIPE)
            sedcmd.stdout.close()

            if exclude is not None:
                stdin.close()

            output = proc1.communicate()[0]

        if patterns is None and exclude is None:
            output = sedcmd.communicate()[0]

        write_file_with_text(archive_path, output.decode('utf-8', 'ignore').strip())


class DataCollector(object):
    '''
    Run commands and collect files
    '''
    def __init__(self, archive_=None, mountpoint=None, target_name=None, target_type='host'):
        self.archive = archive_ if archive_ else archive.InsightsArchive()
        self.mountpoint = '/'
        if mountpoint:
            self.mountpoint = mountpoint
        self.container_name = container_name
        self.target_type = target_type

    def _get_meta_path(self, specname):
        try:
            archive_path = conf['meta_specs'][specname]['archive_file_name']
        except LookupError:
            logger.debug('%s spec not found. Using default.' % specname)
            archive_path = self.archive.get_full_archive_path(
                constants.default_meta_spec[specname])
        return archive_path

    def write_branch_info(self, branch_info):
        logger.debug("Writing branch information to archive...")
        write_file_with_text(_get_meta_path('branch_info'),
                             json.dumps(branch_info))

    def write_analysis_target(self):
        logger.debug('Writing target type to archive...')
        write_file_with_text(_get_meta_path('analysis_target'),
                             self.target_type)

    def write_machine_id(self, machine_id):
        logger.debug('Writing machine-id to archive...')
        write_file_with_text(_get_meta_path('machine-id'),
                             machine_id)

    def _write_uploader_log():
        logger.debug('Writing insights.log to archive...')
        with open(constants.default_log_file) as logfile:
            write_file_with_text(_get_meta_path('uploader_log'),
                                 logfile.strip())

    def _run_pre_command(self, pre_cmd):
        '''
        Run a pre command to get external args for a command
        '''
        logger.debug('Executing pre-command: %s' % pre_cmd)
        try:
            pre_proc = Popen(pre_cmd, stdout=PIPE, stderr=STDOUT, shell=True)
        except OSError as err:
            if err.errno == errno.ENOENT:
                logger.debug('Command %s not found' % pre_cmd)
            return
        stdout, stderr = pre_proc.communicate()
        return stdout.splitlines()

    def _parse_file_spec(spec):
        '''
        Separate wildcard specs into more specs
        '''
        # separate wildcard specs into more specs
        if '*' in spec['file']:
            expanded_paths = _expand_paths(spec['file'])
            if not expanded_paths:
                logger.debug('Could not expand %s' % real_path)
                return []

            expanded_specs = []
            for p in expanded_paths:
                _spec = copy.copy(spec)
                _spec['file'] = p
                expanded_specs.append(_spec)
            return expanded_specs

        else:
            return [spec]

    def _parse_command_spec(spec, precmds):
        '''
        Run pre_commands
        '''
        if 'pre_command' in spec:
            precmd_alias = spec['pre_command']
            precmd = precmds[precmd_alias]
            args = _run_pre_command(precmds[precmd_alias])
            logger.debug('Pre-command results: %s' % args)

            expanded_specs = []
            for arg in args:
                _spec = copy.copy(spec)
                _spec['command'] = _spec['command'] + ' ' + arg
                expanded_specs.append(_spec)
            return expanded_specs

        else:
            return [spec]

    def run_old_collection(self, conf, rm_conf, options):
        # probably wont need to write this
        pass

    def run_collection(self, conf, rm_conf):
        '''
        Run specs and collect all the data
        '''
        logger.debug('Beginning to run collection spec...')
        exclude = None
        if rm_conf:
            try:
                exclude = rm_conf['patterns']
            except LookupError:
                logger.debug('Could not parse remove.conf. Ignoring...')

        if 'spec' not in conf:
            # old style collection
            run_old_collection()
            return

        for spec_group in conf['specs']:
            try:
                spec = spec_group[self.target_type]
                if 'file' in spec:
                    if rm_conf and spec['file'] in rm_conf['files']:
                        logger.warn("WARNING: Skipping file %s", spec['file'])
                        continue
                    else:
                        file_specs = _parse_file_spec(spec)
                        for s in file_specs:
                            file_spec = InsightsFile(s, exclude, self.mountpoint)
                            file_spec.copy_files()
                elif 'command' in spec:
                    if rm_conf and spec['command'] in rm_conf['commands']:
                        logger.warn("WARNING: Skipping command %s", each_spec['command'])
                        continue
                    else:
                        cmd_specs = _parse_command_spec(spec, conf['pre_commands'])
                        for s in cmd_specs:
                            cmd_spec = InsightsCommand(s, exclude, self.mountpoint)
                            self.archive.add_command(cmd_spec)
            except LookupError:
                logger.debug('Target type %s not found in spec. Skipping...' % self.target_type)
                continue
        logger.debug('Spec processing complete.')

    def done(self, config, rm_conf):
        """
        Do finalization stuff
        """
        _write_uploader_log()
        if config.getboolean(APP_NAME, "obfuscate"):
            cleaner = SOSCleaner(quiet=True)
            clean_opts = CleanOptions(self.archive.tmp_dir, config, rm_conf)
            fresh = cleaner.clean_report(clean_opts, self.archive.archive_dir)
            if clean_opts.keyword_file is not None:
                os.remove(clean_opts.keyword_file.name)
            return fresh[0]
        return self.archive.create_tar_file()


class CleanOptions(object):
    """
    Options for soscleaner
    """
    def __init__(self, tmp_dir, config, rm_conf):
        self.report_dir = tmp_dir
        self.domains = []
        self.files = []
        self.quiet = True
        self.keyword_file = None
        self.keywords = None

        if rm_conf:
            try:
                keywords = rm_conf['keywords']
                self.keyword_file = NamedTemporaryFile(delete=False)
                self.keyword_file.write("\n".join(keywords))
                self.keyword_file.flush()
                self.keyword_file.close()
                self.keywords = [self.keyword_file.name]
                logger.debug("Attmpting keyword obfuscation")
            except LookupError:
                pass

        if config.getboolean(APP_NAME, "obfuscate_hostname"):
            self.hostname_path = "insights_commands/hostname"
        else:
            self.hostname_path = None
