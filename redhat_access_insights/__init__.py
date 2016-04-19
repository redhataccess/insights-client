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

# InsightsClient: the global config and options
#   This class was created so that the containers module could get
#     access to config and options without passing them into it, because
#     containers has no obvious single entry function.
#     It would also be useful for other modules too.
#   The class InsightsClient must be defined before any of the other
#     client modules are imported so that they can import it into themselves.
#   Since the InsightsClient values are initialized in main, no one can use
#     these values till after main initializes them.
#   It may also be worth moving functions like containers.get_image_name,
#     and others that only use data gathered from here, into this class.
class InsightsClient:
    pass

import containers

from auto_config import try_auto_configuration
from utilities import (validate_remove_file,
                       generate_machine_id,
                       generate_analysis_target_id,
                       write_lastupload_file,
                       write_registered_file,
                       delete_registered_file,
                       delete_unregistered_file,
                       delete_machine_id)
from collection_rules import InsightsConfig
from data_collector import DataCollector
from schedule import InsightsSchedule
from connection import InsightsConnection
from archive import InsightsArchive
from support import InsightsSupport, registration_check

from constants import InsightsConstants as constants

__author__ = 'Jeremy Crafts <jcrafts@redhat.com>'

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
         'no_schedule': 'False',
         'docker_image_name': None})
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

    if options.to_stdout and not options.verbose:
        options.quiet = True

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
    if options.verbose:
        config_level = 'DEBUG'
    else:
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


def collect_data_and_upload(config, options, rc=0):
    """
    All the heavy lifting done here
    """

    # for now we either collect all containers and images, or we collect the host
    #   because containers are better collected from a container, and
    #   we can yet collect the host from a container
    if options.containers:
        targets = containers.get_targets()
    else:
        targets = [{'type': 'host', 'name': None}]

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

    try:
        stdin_config = {}
        if options.from_file:
            with open(options.from_file, 'r') as f:
                stdin_config = json.load(f)
        elif options.from_stdin:
            stdin_config = json.load(sys.stdin)
        if ((options.from_file or options.from_stdin) and
            ('uploader.json' not in stdin_config or
             'sig' not in stdin_config)):
            raise ValueError
    except:
        logger.error('ERROR: Invalid config for %s! Exiting...' %
                     ('--from-file' if options.from_file else '--from-stdin'))
        return 1

    start = time.clock()
    collection_rules, rm_conf = pc.get_conf(options.update, stdin_config)
    elapsed = (time.clock() - start)
    logger.debug("Collection Rules Elapsed Time: %s", elapsed)

    for t in targets:

        # this try/finally is so that we make sure the archive and container connection
        #  is closed each time through the loop, or if we exit
        container_connection = None
        archive = None
        try:
            if t['type'] == "docker_image":
                container_connection = containers.open_image(t['name'])
                if container_connection:
                    container_fs = container_connection.get_fs()
                else:
                    logger.error('Could not open image for analysis: %s' % t['name'])
                    continue

            elif t['type'] == "docker_container":
                container_connection = containers.open_container(t['name'])
                if container_connection:
                    container_fs = container_connection.get_fs()
                else:
                    logger.error('Could not open container for analysis: %s' % t['name'])
                    continue

            elif t['type'] == "host":
                container_connection = None
                container_fs = None

            else:
                logger.error("Unexpected analysis target: %s" % t['type'])
                continue

            collection_start = time.clock()

            archive = InsightsArchive(compressor=options.compressor,
                                  container_name=t['name'])
            dc = DataCollector(archive,
                               collection_target=t['type'],
                               container_name=t['name'],
                               container_fs=container_fs)

            if options.original_style_specs or "specs" not in collection_rules:
                start = time.clock()
                logger.info('Starting to collect Insights data')
                dc.run_commands(collection_rules, rm_conf)
                elapsed = (time.clock() - start)
                logger.debug("Command Collection Elapsed Time: %s", elapsed)

                start = time.clock()
                dc.copy_files(collection_rules, rm_conf, stdin_config)
                elapsed = (time.clock() - start)
                logger.debug("File Collection Elapsed Time: %s", elapsed)

                dc.write_branch_info(branch_info)

            else:
                start = time.clock()
                dc.process_specs(collection_rules, rm_conf)
                elapsed = (time.clock() - start)
                logger.debug("Data Collection Elapsed Time: %s", elapsed)

                dc.write_analysis_target(t['type'], collection_rules)
                dc.write_machine_id(
                    generate_analysis_target_id(t['type'], t['name']),
                    collection_rules)
                dc.write_branch_info(branch_info, collection_rules)

            obfuscate = config.getboolean(APP_NAME, "obfuscate")

            collection_duration = (time.clock() - collection_start)

            if not options.no_tar_file:
                if options.original_style_specs:
                    tar_file = dc.done(config, rm_conf)
                else:
                    tar_file = dc.done(config, rm_conf, collection_rules=collection_rules)
                if not options.offline:

                    if t['type'] == "docker_image":
                        data_for_what = " for Docker Image %s" % t['name']

                    elif t['type'] == "docker_container":
                        data_for_what = " for Docker Container %s" % t['name']

                    elif t['type'] == "host":
                        data_for_what = ""

                    else: # Unknown type, ignore
                        data_for_what = ""

                    logger.info('Uploading Insights data%s, this may take a few minutes' %
                                data_for_what)
                    for tries in range(options.retries):
                        upload = pconn.upload_archive(tar_file, collection_duration,
                                                      base_name=generate_analysis_target_id(
                                                          t['type'], t['name']))

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

                    if not obfuscate and not options.keep_archive:
                        dc.archive.delete_tmp_dir()
                    else:
                        if obfuscate:
                            logger.info('Obfuscated Insights data retained in %s',
                                        os.path.dirname(tar_file))
                        else:
                            logger.info('Insights data retained in %s', tar_file)
                else:
                    handle_file_output(options, tar_file, archive)
            else:
                logger.info('See Insights data in %s', dc.archive.archive_dir)

        finally:
            if container_connection:
                container_connection.close()
                container_connection = None
            if archive:
                if not (options.keep_archive or options.no_upload):
                    archive.delete_tmp_dir()
                archive = None

    return rc


def handle_file_output(options, tar_file, archive):
    if options.to_stdout:
        shutil.copyfileobj(open(tar_file, 'rb'), sys.stdout)
        archive.delete_tmp_dir()
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
    parser.add_option('--from-file',
                      help='take configuration from file',
                      dest='from_file', action='store',
                      default=False)
    parser.add_option('--offline',
                      help='offline mode for OSP use',
                      dest='offline', action='store_true',
                      default=False)
    parser.add_option('--containers',
                      help='Analyse docker images and containers rather than the host',
                      action='store_true',
                      dest='containers')
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
    group.add_option('--run-here',
                     help="Don't transfer into a container, even for docker analysis",
                     action="store_true",
                     dest="run_here",
                     default=False)
    group.add_option('--original-style-specs',
                     help="Use the original style of specs even if new style are avaliable",
                     action="store_true",
                     dest="original_style_specs",
                     default=False)
    group.add_option('--docker-image-name',
                     help="image name of insights-client",
                     action="store",
                     dest="docker_image_name",
                     default=None)
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

    if options.no_schedule and not options.register:
        InsightsSchedule(set_cron=False).remove_scheduling()
        logger.info('Automatic scheduling for Insights has been removed.')
        sys.exit()

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
        # Set the schedule
        opt_group = options.group
        if os.path.isfile(constants.registered_file):
            logger.info('This host has already been registered.')
        else:
            # double check reg status with the API
            reg_check, status = registration_check(config)
            if not status:
                message, hostname, opt_group, display_name = register(config, options)
                if options.display_name is None and options.group is None:
                    logger.info('Successfully registered %s', hostname)
                elif options.display_name is None:
                    logger.info('Successfully registered %s in group %s', hostname, opt_group)
                else:
                    logger.info('Successfully registered %s as %s in group %s', hostname, display_name,
                                opt_group)
                logger.info(message)
            else:
                logger.info('This host has already been registered.')
                # regenerate the .registered file
                write_registered_file()
        if not options.no_schedule and not config.getboolean(
                APP_NAME, 'no_schedule'):
            InsightsSchedule()
            logger.info('Automatic daily scheduling for Insights has been enabled.')

    # Collect debug/log information
    if options.support:
        support = InsightsSupport(config)
        support.collect_support_info()
        sys.exit(0)

    # Just check registration status
    if options.status:
        reg_check, status = registration_check(config)
        logger.info('\n'.join(reg_check))
        # exit with !status, 0 for True, 1 for False
        sys.exit(not status)

    # Set offline mode for OSP/RHEV use
    if options.no_upload:
        options.offline = True

    # Can't use both
    if options.from_stdin and options.from_file:
        logger.error('Can\'t use both --from-stdin and --from-file.')
        sys.exit(1)

    if not options.run_here and options.containers and \
       containers.insights_client_container_is_available():
        sys.exit(containers.run_in_container(options))

    # First startup, no .registered or .unregistered
    # Ignore if in offline mode
    if (not os.path.isfile(constants.registered_file) and
       not os.path.isfile(constants.unregistered_file) and
       not options.register and not options.offline):
        logger.error('This machine has not yet been registered.')
        logger.error('Use --register to register this machine.')
        logger.error("Exiting")
        sys.exit(1)

    # Check for .unregistered file
    if (os.path.isfile(constants.unregistered_file) and
       not options.register and not options.offline):
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
    options.to_stdout = options.to_stdout or options.from_stdin or options.from_file

    config = parse_config_file(options.conf)
    logger, handler = set_up_logging(config, options)

    InsightsClient.options = options
    InsightsClient.config = config
    InsightsClient.argv = sys.argv

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
