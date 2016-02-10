#!/usr/bin/python
"""
 Gather and Upload Insights Data for
 Red Hat Access Insights
"""
import ConfigParser
import getpass
import inspect
import json
import logging
import logging.handlers
import optparse
import os
import requests
import shutil
import sys
import time
import traceback
import atexit
from auto_config import try_auto_configuration
from utilities import (validate_remove_file,
                       generate_machine_id,
                       write_lastupload_file,
                       delete_registered_file,
                       delete_unregistered_file,
                       delete_machine_id)
from collection_rules import InsightsConfig
from data_collector import DataCollector
from schedule import InsightsSchedule
from connection import InsightsConnection
from archive import InsightsArchive
from support import InsightsSupport

from constants import InsightsConstants as constants

__author__ = 'Dan Varga <dvarga@redhat.com>'

LOG_FORMAT = ("%(asctime)s %(levelname)s %(message)s")
APP_NAME = constants.app_name
logger = None


def parse_config_file(conf_file):
    """
    Parse the configuration from the file
    """
    parsedconfig = ConfigParser.RawConfigParser(
        {'loglevel': constants.log_level,
         'trace': 'False',
         'app_name': constants.app_name,
         'auto_config': 'True',
         'authmethod': constants.auth_method,
         'base_url': constants.base_url,
         'upload_url': None,
         'api_url': None,
         'branch_info_url': None,
         'auto_update': 'True',
         'collection_rules_url': None,
         'obfuscate': 'False',
         'obfuscate_hostname': 'False',
         'cert_verify': constants.default_ca_file,
         'gpg': 'True',
         'username': '',
         'password': '',
         'systemid': None,
         'proxy': None,
         'insecure_connection': 'False',
         'no_schedule': 'False'})
    try:
        parsedconfig.read(conf_file)
    except ConfigParser.Error:
        logger.error("ERROR: Could not read configuration file, using defaults")
    try:
        # Try to add the redhat_access_insights section
        parsedconfig.add_section(APP_NAME)
    except ConfigParser.Error:
        pass
    return parsedconfig


def set_up_logging(config, options):
    """
    Initialize Logging
    """
    log_dir = constants.log_dir
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, 0700)
    logging_file = os.path.join(log_dir, APP_NAME + '.log')

    valid_levels = ['ERROR', 'DEBUG', 'INFO', 'WARNING', 'CRITICAL']

    handler = logging.handlers.RotatingFileHandler(logging_file,
                                                   backupCount=3)

    # Send anything INFO+ to stdout and log
    stdout_handler = logging.StreamHandler(sys.stdout)
    if not options.verbose:
        stdout_handler.setLevel(logging.INFO)
    if options.quiet:
        stdout_handler.setLevel(logging.ERROR)
    if not options.silent:
        logging.root.addHandler(stdout_handler)

    logging.root.addHandler(handler)

    formatter = logging.Formatter(LOG_FORMAT)
    handler.setFormatter(formatter)
    logging.root.setLevel(logging.WARNING)
    my_logger = logging.getLogger(APP_NAME)
    config_level = config.get(APP_NAME, 'loglevel')
    if config_level in valid_levels:
        init_log_level = logging.getLevelName(config_level)
    else:
        print "Invalid log level %s, defaulting to DEBUG" % config_level
        init_log_level = logging.getLevelName("DEBUG")

    my_logger.setLevel(init_log_level)
    logging.root.setLevel(init_log_level)
    my_logger.debug("Logging initialized")
    return my_logger, handler


def handle_exception(exc_type, exc_value, exc_traceback):
    """
    Exception handler so exception messages land in our log instead of them
    vanishing into thin air, or abrt picking them up
    """
    if issubclass(exc_type, KeyboardInterrupt):
        sys.exit(1)
    if logger:
        logger.error(
            traceback.format_exception(exc_type, exc_value, exc_traceback))
    else:
        print traceback.format_exception(exc_type, exc_value, exc_traceback)
        sys.exit('Caught unhandled exception, check log for more information')


def lineno():
    """
    Get lineno
    """
    return inspect.currentframe().f_back.f_lineno


def handle_branch_info_error(msg, options):
    if options.no_upload:
        logger.warning(msg)
        logger.warning("Assuming remote branch and leaf value of -1")
        branch_info = {}
        branch_info['remote_branch'] = branch_info['remote_leaf'] = -1
        return branch_info
    else:
        logger.error("ERROR: %s", msg)
        sys.exit()


def handle_exit(archive, keep_archive):
    # delete the archive on exit so we don't keep crap around
    if not keep_archive:
        archive.delete_tmp_dir()


def collect_data_and_upload(config, options, rc=0):
    """
    All the heavy lifting done here
    """
    collection_start = time.clock()

    pconn = InsightsConnection(config)
    try:
        branch_info = pconn.branch_info()
    except requests.ConnectionError:
        branch_info = handle_branch_info_error(
            "Could not connect to determine branch information", options)
    except LookupError:
        branch_info = handle_branch_info_error(
            "Could not determine branch information", options)
    pc = InsightsConfig(config, pconn)
    archive = InsightsArchive(compressor=options.compressor,
                              container_name=options.container_name)
    dc = DataCollector(archive, container_name=options.container_name)

    # register the exit handler here to delete the archive
    atexit.register(handle_exit, archive, options.keep_archive or options.no_upload)

    stdin_config = json.load(sys.stdin) if options.from_stdin else {}

    start = time.clock()
    collection_rules, rm_conf = pc.get_conf(options.update, stdin_config)
    elapsed = (time.clock() - start)
    logger.debug("Collection Rules Elapsed Time: %s", elapsed)

    if options.container_mode and not os.path.isdir(options.container_fs):
        logger.error('Invalid path specified for --fs')
        sys.exit(1)

    start = time.clock()
    logger.info('Starting to collect Insights data')
    dc.run_commands(collection_rules, rm_conf, options.container_fs)
    elapsed = (time.clock() - start)
    logger.debug("Command Collection Elapsed Time: %s", elapsed)

    start = time.clock()
    dc.copy_files(collection_rules, rm_conf, options.container_fs)
    elapsed = (time.clock() - start)
    logger.debug("File Collection Elapsed Time: %s", elapsed)

    dc.write_branch_info(branch_info)
    obfuscate = config.getboolean(APP_NAME, "obfuscate")

    collection_duration = (time.clock() - collection_start)

    if not options.no_tar_file:
        tar_file = dc.done(config, rm_conf)
        if not options.no_upload:
            logger.info('Uploading Insights data,'
                        ' this may take a few minutes')
            for tries in range(options.retries):
                upload = pconn.upload_archive(tar_file, collection_duration)
                if upload.status_code == 201:
                    write_lastupload_file()
                    logger.info("Upload completed successfully!")
                    break
                elif upload.status_code == 412:
                    pconn.handle_fail_rcs(upload)
                else:
                    logger.error("Upload attempt %d of %d failed! Status Code: %s",
                                 tries + 1, options.retries, upload.status_code)
                    if tries + 1 != options.retries:
                        logger.info("Waiting %d seconds then retrying",
                                    constants.sleep_time)
                        time.sleep(constants.sleep_time)
                    else:
                        logger.error("All attempts to upload have failed!")
                        logger.error("Please see %s for additional information",
                                     constants.default_log_file)
                        rc = 1

            if (not obfuscate and not options.keep_archive):
                dc.archive.delete_tmp_dir()
            else:
                if obfuscate:
                    logger.info('Obfuscated Insights data retained in %s',
                                os.path.dirname(tar_file))
                else:
                    logger.info('Insights data retained in %s', tar_file)
        else:
            handle_file_output(options, tar_file)
    else:
        logger.info('See Insights data in %s', dc.archive.archive_dir)
    return rc


def handle_file_output(options, tar_file):
    if options.to_stdout:
        shutil.copyfileobj(open(tar_file, 'rb'), sys.stdout)
        os.unlink(tar_file)
    else:
        logger.info('See Insights data in %s', tar_file)


def register(config, group_id=None):
    """
    Do registration using basic auth
    """
    username = config.get(APP_NAME, 'username')
    password = config.get(APP_NAME, 'password')
    if ((
            username == "" and
            password == "" and
            config.get(APP_NAME, 'authmethod') == 'BASIC')
        and
            not config.get(APP_NAME, 'auto_config')):
        # Get input from user
        print "Please enter your Red Hat Customer Portal Credentials"
        sys.stdout.write('User Name: ')
        username = raw_input().strip()
        password = getpass.getpass()
        sys.stdout.write("Would you like to save these credentials? (y/n) ")
        save = raw_input().strip()
        config.set(APP_NAME, 'username', username)
        config.set(APP_NAME, 'password', password)
        logger.debug("savestr: %s", save)
        if save.lower() == "y" or save.lower() == "yes":
            logger.debug("writing user/pass to config file")
            cmd = ("/bin/sed -e 's/^username.*=.*$/username=" +
                   username + "/' " +
                   "-e 's/^password.*=.*$/password=" + password + "/' " +
                   constants.default_conf_file)
            status = DataCollector().run_command_get_output(cmd, nolog=True)
            config_file = open(constants.default_conf_file, 'w')
            config_file.write(status['output'])
            config_file.flush()

    pconn = InsightsConnection(config)
    return pconn.register(group_id)


def set_up_options(parser):
    """
    Add options to the option parser
    """
    parser.add_option('--version',
                      help="Display version",
                      action="store_true",
                      dest="version",
                      default=False)
    parser.add_option('--register',
                      help=('Register system to the Red Hat '
                            'Access Insights Service'),
                      action="store_true",
                      dest="register",
                      default=False)
    parser.add_option('--unregister',
                      help=('Unregister system from the Red Hat '
                            'Access Insights Service'),
                      action="store_true",
                      dest="unregister",
                      default=False)
    parser.add_option('--update-collection-rules',
                      help='Refresh collection rules from Red Hat',
                      action="store_true",
                      dest="update",
                      default=False)
    parser.add_option('--display-name',
                      action="store",
                      help='Display name for this system.  '
                           'Must be used with --register',
                      dest="display_name")
    parser.add_option('--group',
                      action="store",
                      help='Group to add this system to during registration',
                      dest="group")
    parser.add_option('--retry',
                      action="store",
                      type="int",
                      help=('Number of times to retry uploading. '
                            '%s seconds between tries'
                            % constants.sleep_time),
                      default=1,
                      dest="retries")
    parser.add_option('--validate',
                      help='Validate remove.conf',
                      action="store_true",
                      dest="validate",
                      default=False)
    parser.add_option('--quiet',
                      help='Only display error messages to stdout',
                      action="store_true",
                      dest="quiet",
                      default=False)
    parser.add_option('--silent',
                      help='Display no messages to stdout',
                      action="store_true",
                      dest="silent",
                      default=False)
    parser.add_option('--no-schedule',
                      help='Disable automatic scheduling',
                      action='store_true',
                      dest='no_schedule',
                      default=False)
    parser.add_option('-c', '--conf',
                      help="Pass a custom config file",
                      dest="conf",
                      default=constants.default_conf_file)
    parser.add_option('--to-stdout',
                      help='print archive to stdout; '
                           'sets --silent and --no-upload',
                      dest='to_stdout',
                      default=False,
                      action='store_true')
    parser.add_option('--compressor',
                      help='specify alternate compression '
                           'algorithm (gz, bzip2, xz, none; defaults to gz)',
                      dest='compressor',
                      default='gz')
    parser.add_option('--from-stdin',
                      help='take configuration from stdin',
                      dest='from_stdin', action='store_true',
                      default=False)
    parser.add_option('--offline',
                      help='offline mode for OSP use',
                      dest='offline', action='store_true',
                      default=False)
    parser.add_option('--container',
                      help='Run Insights in container mode.',
                      action='store_true',
                      dest='container_mode')
    parser.add_option('--fs',
                      help='Absolute path to mounted filesystem to run Insights against. '
                           'Only valid when --container is used',
                      action='store',
                      dest='container_fs')
    parser.add_option('--name',
                      help='Name to use for mounted container filesystem. '
                           'Only valid when --container is used',
                      action='store',
                      dest='container_name')
    group = optparse.OptionGroup(parser, "Debug options")
    group.add_option('--test-connection',
                     help='Test connectivity to Red Hat',
                     action="store_true",
                     dest="test_connection",
                     default=False)
    group.add_option('--force-reregister',
                     help=("Forcefully reregister this machine to Red Hat. "
                           "Use only as directed."),
                     action="store_true",
                     dest="reregister",
                     default=False)
    group.add_option('--verbose',
                     help="DEBUG output to stdout",
                     action="store_true",
                     dest="verbose",
                     default=False)
    group.add_option('--support',
                     help="Create a support logfile for Red Hat Insights",
                     action="store_true",
                     dest="support",
                     default=False)
    group.add_option('--status',
                     help="Check this machine's registration status with Red Hat Insights",
                     action="store_true",
                     dest="status",
                     default=False)
    group.add_option('--no-gpg',
                     help="Do not verify GPG signature",
                     action="store_true",
                     dest="no_gpg",
                     default=False)
    group.add_option('--no-upload',
                     help="Do not upload the archive",
                     action="store_true",
                     dest="no_upload",
                     default=False)
    group.add_option('--no-tar-file',
                     help="Build the directory, but do not tar",
                     action="store_true",
                     dest="no_tar_file",
                     default=False)
    group.add_option('--keep-archive',
                     help="Do not delete archive after upload",
                     action="store_true",
                     dest="keep_archive",
                     default=False)
    parser.add_option_group(group)


def handle_startup(options, config):
    """
    Handle startup options
    """

    if options.version:
        print constants.version
        sys.exit()

    if options.validate:
        validate_remove_file()
        sys.exit()

    # Generate /etc/machine-id if it does not exist
    new = False
    # force-reregister -- remove machine-id files nd registration files before trying to register again
    if options.reregister:
        new = True
        options.register = True
        delete_registered_file()
        delete_unregistered_file()
        delete_machine_id()
    logger.debug("Machine-ID: " + generate_machine_id(new))

    # Disable GPG verification
    if options.no_gpg:
        logger.warn("WARNING: GPG VERIFICATION DISABLED")
        config.set(APP_NAME, 'gpg', 'False')

    # Log config except the password
    # and proxy as it might have a pw as well
    for item, value in config.items(APP_NAME):
        if item != 'password' and item != 'proxy':
            logger.debug("%s:%s", item, value)

    if config.getboolean(APP_NAME, 'auto_update'):
        options.update = True

    if config.getboolean(APP_NAME, 'auto_config'):
        # Try to discover if we are connected to a satellite or not
        try_auto_configuration(config)

    # Set the schedule
    if not options.no_schedule and not config.getboolean(
            APP_NAME, 'no_schedule'):
        InsightsSchedule()

    # Test connection, useful for proxy debug
    if options.test_connection:
        pconn = InsightsConnection(config)
        pconn.test_connection()

    if options.unregister:
        pconn = InsightsConnection(config)
        pconn.unregister()
        sys.exit()

    # Handle registration, grouping, and display name
    if options.register:
        opt_group = options.group
        message, hostname, opt_group, display_name = register(config, options)
        if options.display_name is None and options.group is None:
            logger.info('Successfully registered %s', hostname)
        elif options.display_name is None:
            logger.info('Successfully registered %s in group %s', hostname, opt_group)
        else:
            logger.info('Successfully registered %s as %s in group %s', hostname, display_name,
                        opt_group)

        logger.info(message)

    # Collect debug/log information
    if options.support:
        support = InsightsSupport(config)
        support.collect_support_info()
        sys.exit(0)

    # Just check registration status
    if options.status:
        support = InsightsSupport(config)
        reg_check = support.registration_check()
        logger.info('\n'.join(reg_check))
        sys.exit(0)

    # Set offline mode for OSP use
    offline_mode = False
    if (options.offline and options.from_stdin) or options.no_upload:
        offline_mode = True

    # blank these out if --container not set
    if not options.container_mode:
        options.container_fs = None
        options.container_name = None

    # First startup, no .registered or .unregistered
    # Ignore if in offline mode
    if (not os.path.isfile(constants.registered_file) and
       not os.path.isfile(constants.unregistered_file) and
       not options.register and not offline_mode):
        logger.error('This machine has not yet been registered.')
        logger.error('Use --register to register this machine.')
        logger.error("Exiting")
        sys.exit(1)

    # Check for .unregistered file
    if (os.path.isfile(constants.unregistered_file) and
       not options.register and not offline_mode):
        logger.error("This machine has been unregistered.")
        logger.error("Use --register if you would like to re-register this machine.")
        logger.error("Exiting")
        sys.exit(1)


def _main():
    """
    Main entry point
    Parse cmdline options
    Parse config file
    Call data collector
    """
    if os.geteuid() is not 0:
        sys.exit("Red Hat Access Insights must be run as root")

    global logger
    sys.excepthook = handle_exception

    parser = optparse.OptionParser()
    set_up_options(parser)
    options, args = parser.parse_args()
    if len(args) > 0:
        parser.error("Unknown arguments: %s" % args)
        sys.exit(1)

    # from_stdin mode implies to_stdout
    options.to_stdout = options.to_stdout or options.from_stdin

    if options.to_stdout:
        options.silent = True
        options.no_upload = True

    config = parse_config_file(options.conf)
    logger, handler = set_up_logging(config, options)

    if config.getboolean(APP_NAME, 'trace'):
        sys.settrace(trace_calls)

    # Defer logging till it's ready
    logger.debug('invoked with args: %s', options)
    logger.debug("Version: " + constants.version)

    # Handle all the options
    handle_startup(options, config)

    # do work
    rc = collect_data_and_upload(config, options)

    # Roll log over on successful upload
    handler.doRollover()

    sys.exit(rc)


def trace_calls(frame, event, arg):
    if event != 'call':
        return
    co = frame.f_code
    func_name = co.co_name
    if func_name == 'write':
        return
    func_line_no = frame.f_lineno
    func_filename = co.co_filename
    caller = frame.f_back
    caller_line_no = caller.f_lineno
    caller_filename = caller.f_code.co_filename
    print 'Call to %s on line %s of %s from line %s of %s' % \
        (func_name, func_line_no, func_filename,
         caller_line_no, caller_filename)
    return

if __name__ == '__main__':
    _main()
