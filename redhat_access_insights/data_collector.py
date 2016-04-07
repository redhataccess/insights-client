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
import copy
from tempfile import NamedTemporaryFile
from soscleaner import SOSCleaner
from utilities import determine_hostname, _expand_paths, write_file_with_text, generate_container_id
from constants import InsightsConstants as constants
from insights_spec import InsightsFile, InsightsCommand

APP_NAME = constants.app_name
logger = logging.getLogger(APP_NAME)
# python 2.7
SOSCLEANER_LOGGER = logging.getLogger('soscleaner')
SOSCLEANER_LOGGER.setLevel(logging.ERROR)
# python 2.6
SOSCLEANER_LOGGER = logging.getLogger('redhat_access_insights.soscleaner')
SOSCLEANER_LOGGER.setLevel(logging.ERROR)


class DataCollector(object):
    '''
    Run commands and collect files
    '''
    def __init__(self, archive_=None, mountpoint=None, container_name=None, target_type='host'):
        self.archive = archive_ if archive_ else archive.InsightsArchive()
        self.mountpoint = '/'
        if mountpoint:
            self.mountpoint = mountpoint
        self.container_name = container_name
        self.target_type = target_type

    def _get_meta_path(self, specname, conf):
        try:
            archive_path = conf['meta_specs'][specname]['archive_file_name']
        except LookupError:
            logger.debug('%s spec not found. Using default.' % specname)
            archive_path = self.archive.get_full_archive_path(
                constants.default_meta_spec[specname])
        return archive_path

    def write_branch_info(self, branch_info, conf):
        logger.debug("Writing branch information to archive...")
        write_file_with_text(self._get_meta_path('branch_info', conf),
                             json.dumps(branch_info))

    def write_analysis_target(self, conf):
        logger.debug('Writing target type to archive...')
        write_file_with_text(self._get_meta_path('analysis_target', conf),
                             self.target_type)

    def write_machine_id(self, machine_id, conf):
        logger.debug('Writing machine-id to archive...')
        write_file_with_text(self._get_meta_path('machine-id', conf),
                             machine_id)

    def _write_uploader_log(self, conf):
        logger.debug('Writing insights.log to archive...')
        with open(constants.default_log_file) as logfile:
            write_file_with_text(self._get_meta_path('uploader_log', conf),
                                 logfile.read().strip())

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

    def _parse_file_spec(self, spec):
        '''
        Separate wildcard specs into more specs
        '''
        # separate wildcard specs into more specs
        if '*' in spec['file']:
            expanded_paths = _expand_paths(spec['file'])
            if not expanded_paths:
                logger.debug('Could not expand %s' % spec['file'])
                return []

            expanded_specs = []
            for p in expanded_paths:
                _spec = copy.copy(spec)
                _spec['file'] = p
                expanded_specs.append(_spec)
            return expanded_specs

        else:
            return [spec]

    def _parse_command_spec(self, spec, precmds):
        '''
        Run pre_commands
        '''
        if 'pre_command' in spec:
            precmd_alias = spec['pre_command']
            precmd = precmds[precmd_alias]
            args = self._run_pre_command(precmds[precmd_alias])
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

        # if 'spec' not in conf:
        #     # old style collection
        #     run_old_collection()
        #     return

        for specname in conf['specs']:
            try:
                # spec group for a symbolic name
                spec_group = conf['specs'][specname]
                # list of specs for a target
                # there might be more than one spec (for compatability)
                spec_list = spec_group[self.target_type]
                for spec in spec_list:
                    if 'file' in spec:
                        if rm_conf and spec['file'] in rm_conf['files']:
                            logger.warn("WARNING: Skipping file %s", spec['file'])
                            continue
                        else:
                            file_specs = self._parse_file_spec(spec)
                            for s in file_specs:
                                processed_spec = InsightsFile(s, exclude, self.mountpoint)
                    elif 'command' in spec:
                        if rm_conf and spec['command'] in rm_conf['commands']:
                            logger.warn("WARNING: Skipping command %s", each_spec['command'])
                            continue
                        else:
                            cmd_specs = self._parse_command_spec(spec, conf['pre_commands'])
                            for s in cmd_specs:
                                processed_spec = InsightsCommand(s, exclude, self.mountpoint)
                    self.archive.add_to_archive(processed_spec)
            except LookupError:
                logger.debug('Target type %s not found in spec. Skipping...' % self.target_type)
                continue
        logger.debug('Spec processing complete.')

    def done(self, config, conf, rm_conf):
        """
        Do finalization stuff
        """
        self._write_uploader_log(conf)
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
