#!/usr/bin/python
"""
 Gather and upload Insights data for
 Red Hat Insights
"""
import ConfigParser
import getpass
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
                       generate_analysis_target_id,
                       write_lastupload_file,
                       write_registered_file,
                       delete_registered_file,
                       delete_unregistered_file,
                       delete_machine_id,
                       determine_hostname,
                       write_lastupload_file)
from collection_rules import InsightsConfig
from data_collector import DataCollector
from schedule import InsightsSchedule
from connection import InsightsConnection
from archive import InsightsArchive
from support import InsightsSupport, registration_check
from constants import InsightsConstants as constants
from containers import open_image, get_images, run_in_container

__author__ = 'Jeremy Crafts <jcrafts@redhat.com>'

LOG_FORMAT = ("%(asctime)s %(levelname)s %(message)s")
APP_NAME = constants.app_name
logger = None


def set_up_logging(config, options):
    # TODO: come back to this
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

    # from_stdin mode implies to_stdout
    options.to_stdout = (options.to_stdout or
                         options.from_stdin or
                         options.from_file)
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


def set_up_options(parser):
    """
    Add options to the option parser
    """
    parser.add_option('--register',
                      help=('Register system to the Red Hat '
                            'Insights Service'),
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
    parser.add_option('--container',
                      help='Run Insights in container mode.',
                      action='store_true',
                      dest='container_mode')
    parser.add_option('--run-as-container',
                      help="Run analysis from a container",
                      action="store_true",
                      dest="run_as_container",
                      default=False)
    group = optparse.OptionGroup(parser, "Debug options")
    parser.add_option('--version',
                      help="Display version",
                      action="store_true",
                      dest="version",
                      default=False)
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
    '''
    [main options]
    --version (move to debug section?)
    --register
    --unregister
    --update-collection-rules
    --display-name
    --group
    --retry
    --validate
    --quiet
    --silent
    --no-schedule <-- change this to something more usable
    ?--enable-schedule
    ?--disable-schedule
    ?--schedule=True/False
    --conf / -c
    --to-stdout
    --compressor
    --from-stdin
    --from-file
    --offline
    --no-upload (redundant w/ --offline)
    --container (change to --docker?)
    --run-as-container
    [debug options]
    --test-connection
    --force-reregister
    --verbose
    --support
    --status
    --no-gpg
    --no-upload
    --no-tar-file
    --keep-archive
    '''


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


def handle_startup(config, options):
    """
    Handle startup options
    """
    # ----do X and exit options----
    # show version and exit
    if options.version:
        print constants.version
        sys.exit()

    if options.run_as_container:
        options.run_as_container = False
        sys.exit(run_in_container(sys.argv[1:]))

    if options.validate:
        validate_remove_file()
        sys.exit()

    if options.test_connection:
        pconn = InsightsConnection(config)
        rc = pconn.test_connection()
        sys.exit(rc)

    if options.status:
        reg_check, status = registration_check(config)
        logger.info('\n'.join(reg_check))
        # exit with !status, 0 for True, 1 for False
        sys.exit(not status)

    if options.support:
        support = InsightsSupport(config)
        support.collect_support_info()
        sys.exit()

    # ----config options----
    # log the config
    # ignore password and proxy -- proxy might have pw
    for item, value in config.items(APP_NAME):
        if item != 'password' and item != 'proxy':
            logger.debug("%s:%s", item, value)

    if config.getboolean(APP_NAME, 'auto_update'):
        # TODO: config updates option, but in GPG option, the option updates
        # the config.  make this consistent
        options.update = True

    if config.getboolean(APP_NAME, 'auto_config'):
        # Try to discover if we are connected to a satellite or not
        try_auto_configuration(config)

    # ----modifier options----
    if options.no_gpg:
        logger.warn("WARNING: GPG VERIFICATION DISABLED")
        config.set(APP_NAME, 'gpg', 'False')

    if options.no_upload:
        options.offline = True

    if options.from_stdin and options.from_file:
        logger.error('Can\'t use both --from-stdin and --from-file.')
        sys.exit(1)

    # ----register options----
    # put this first to avoid conflicts with register
    if options.unregister:
        pconn = InsightsConnection(config)
        pconn.unregister()
        sys.exit()

    # force-reregister -- remove machine-id files nd registration files before trying to register again
    # TODO: I don't like the way this looks
    new = False
    if options.reregister:
        new = True
        options.register = True
        delete_registered_file()
        delete_unregistered_file()
        delete_machine_id()
    logger.debug('Machine-id: %s' % generate_machine_id(new))

    if options.register:
        try_register(config, options)


def handle_branch_info_error(msg, options):
    if options.offline:
        logger.warning(msg)
        logger.warning("Assuming remote branch and leaf value of -1")
        return {'remote_branch': -1,
                'remote_leaf': -1}
    else:
        logger.error("ERROR: %s", msg)
        sys.exit()


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


def _delete_archive(archive, keep_archive):
    # delete the archive on exit so we don't keep crap around
    if not keep_archive:
        archive.delete_tmp_dir()


def _unmount_image(image):
    try:
        mounted_image.close()
    except:
        # it was already unmounted
        pass


def try_register(config, options):
    if os.path.isfile(constants.registered_file):
        logger.info('This host has already been registered.')
        return
    # check reg status with API
    reg_check, status = registration_check(config)
    if status:
        logger.info('This host has already been registered.')
        # regenerate the .registered file
        write_registered_file()
        return
    message, hostname, group, display_name = register(config, options)
    if options.display_name is None and options.group is None:
        logger.info('Successfully registered %s' % hostname)
    elif options.display_name is None:
        logger.info('Successfully registered %s in group %s' % (hostname, group))
    else:
        logger.info('Successfully registered %s as %s in group %s' % (
            hostname, display_name, group))
    if message:
        logger.info(message)


def register(config, options):
    """
    Do registration using basic auth
    """
    username = config.get(APP_NAME, 'username')
    password = config.get(APP_NAME, 'password')
    authmethod = config.get(APP_NAME, 'authmethod')
    # TODO validate this is boolean somewhere in config load
    auto_config = config.getboolean(APP_NAME, 'auto_config')
    if not username and not password and not auto_config and authmethod == 'BASIC':
        print 'Please enter your Red Hat Customer Portal Credentials'
        sys.stdout.write('Username: ')
        username = raw_input().strip()
        password = getpass.getpass()
        sys.stdout.write('Would you like to save these credentials? (y/n) ')
        save = raw_input().strip()
        config.set(APP_NAME, 'username', username)
        config.set(APP_NAME, 'password', password)
        logger.debug('savestr: %s' % save)
        if save.lower() == 'y' or save.lower() == 'yes':
            logger.debug('Writing user/pass to config')
            cmd = ('/bin/sed -e \'s/^username.*=.*$/username=' +
                   username + '/\' ' +
                   '-e \'s/^password.*=.*$/password=' + password + '/\' ' +
                   constants.default_conf_file)
            status = DataCollector().run_command_get_output(cmd, nolog=True)
            with open(constants.default_conf_file, 'w') as config_file:
                config_file.write(status['output'])
                config_file.flush()
    pconn = InsightsConnection(config)
    return pconn.register(options)


def collect_data_and_upload(config, options, rc=0):
    """
    All the heavy lifting done here
    Run through "targets" - could be just one (host, default) or many (containers+host)
    """
    # initialize collection targets
    if options.container_mode:
        targets = get_images()
        if targets:
            # TODO: use 'host-limited' as the type for container host data
            # or something else Gavin may have concocted
            targets.append({'type': 'host', 'name': None})
        else:
            # container mode, but no images, abort
            # error msg will come from get_images()
            sys.exit(1)
    else:
        targets = constants.default_target

    pconn = InsightsConnection(config)
    # TODO: change these err msgs to be more meaningful , i.e.
    # "could not determine login information"
    try:
        branch_info = pconn.branch_info()
    except requests.ConnectionError:
        branch_info = handle_branch_info_error(
            "Could not connect to determine branch information", options)
    except LookupError:
        branch_info = handle_branch_info_error(
            "Could not determine branch information", options)
    pc = InsightsConfig(config, pconn)

    # load config from stdin/file if specified
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
        sys.exit(1)

    start = time.clock()
    collection_rules, rm_conf = pc.get_conf(options.update, stdin_config)
    collection_elapsed = (time.clock() - start)
    logger.debug("Rules configuration loaded. Elapsed time: %s", collection_elapsed)

    for t in targets:
        # default mountpoint
        mp = None
        # mount if the target is an image
        if t['type'] == 'docker_image':
            mounted_image = open_image(t['name'])
            mp = mounted_image.mount_point
            # unmount on unexpected exit
            atexit.register(_unmount_image, mounted_image)

        collection_start = time.clock()
        archive = InsightsArchive(compressor=options.compressor, container_name=t['name'])
        dc = DataCollector(archive, mountpoint=mp, container_name=t['name'], target_type=t['type'])
        logging_name = determine_hostname() if t['name'] is None else t['name']

        # delete the archive on unexpected exit
        atexit.register(_delete_archive, archive, options.keep_archive or options.no_upload)

        logger.info('Starting to collect Insights data for %s' % logging_name)

        # spec version
        if 'specs' in collection_rules:
            dc.process_specs(collection_rules, rm_conf, options)
            elapsed = (time.clock() - start)
            logger.debug("Data collection complete. Elapsed time: %s", elapsed)

            dc.write_analysis_target(options.collection_target, collection_rules)
            dc.write_machine_id(
                generate_analysis_target_id(t['type'], t['name']),
                collection_rules)
            dc.write_branch_info(branch_info, collection_rules)
        # original version
        else:
            dc.run_commands(collection_rules, rm_conf)
            elapsed = (time.clock() - start)
            logger.debug("Command execution complete. Elapsed time: %s", elapsed)

            start = time.clock()
            dc.copy_files(collection_rules, rm_conf, stdin_config)
            elapsed = (time.clock() - start)
            logger.debug("File collection complete. Elapsed time: %s", elapsed)

            dc.write_branch_info(branch_info)
            obfuscate = config.getboolean(APP_NAME, "obfuscate")

        # include rule refresh time in the duration
        collection_duration = (time.clock() - collection_start) + collection_elapsed

        # unmount image when we are finished
        if t['type'] == 'docker_image':
            mounted_image.close()

        if options.no_tar_file:
            logger.info('See Insights data in %s', dc.archive.archive_dir)
            return rc

        tar_file = dc.done(config, rm_conf)

        if options.offline:
            handle_file_output(options, tar_file, archive)
            return rc

        # do the upload
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

        if obfuscate:
            logger.info('Obfuscated Insights data retained in %s',
                        os.path.dirname(tar_file))
        elif options.keep_archive:
            logger.info('Insights data retained in %s', tar_file)
        else:
            dc.archive.delete_tmp_dir()


def handle_file_output(options, tar_file, archive):
    if options.to_stdout:
        shutil.copyfileobj(open(tar_file, 'rb'), sys.stdout)
        archive.delete_tmp_dir()
    else:
        logger.info('See Insights data in %s', tar_file)


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
    config = parse_config_file(options.conf)
    logger, handler = set_up_logging(config, options)

    if config.getboolean(APP_NAME, 'trace'):
        sys.settrace(trace_calls)

    # Defer logging till it's ready
    logger.debug('invoked with args: %s', options)
    logger.debug("Version: " + constants.version)

    # Handle all the options
    handle_startup(config, options)

    # Vaccuum up the data
    rc = collect_data_and_upload(config, options)

    # Roll log over on successful upload
    handler.doRollover()
    sys.exit(rc)

if __name__ == '__main__':
    _main()
