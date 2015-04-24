#!/usr/bin/python
"""
 Gather and Upload Insights Data for
 Red Hat Access Insights
"""
import os
import sys
import logging
import inspect
import traceback
import logging.handlers
import ConfigParser
import getpass
import optparse
import time
from utilities import (get_satellite_group,
                       validate_remove_file,
                       generate_machine_id)
from cert_auth import rhsmCertificate
from dynamic_config import InsightsConfig
from data_collector import DataCollector
from schedule import InsightsSchedule
from connection import InsightsConnection

from constants import InsightsConstants as constants

if os.geteuid() is not 0:
    sys.exit("Red Hat Access Insights must be run as root")

__author__ = 'Dan Varga <dvarga@redhat.com>'

LOG_FORMAT = ("%(asctime)s - %(name)s - %(levelname)s "
              "- (%(threadName)-10s) %(message)s")
APP_NAME = constants.app_name
logger = None


def parse_config_file():
    """
    Parse the configuration from the file
    """
    parsedconfig = ConfigParser.RawConfigParser(
        {'loglevel': constants.log_level,
         'app_name': constants.app_name,
         'auto_config': 'False',
         'authmethod': constants.auth_method,
         'upload_url': constants.upload_url,
         'api_url': constants.api_url,
         'branch_info_url': constants.branch_info_url,
         'auto_update': 'True',
         'dynamic_config_url': constants.dynamic_conf_url,
         'obfuscate': 'False',
         'obfuscate_hostname': 'False',
         'cert_verify': constants.default_ca_file,
         'gpg': 'True',
         'username': '',
         'password': '',
         'proxy': None})
    try:
        parsedconfig.read(constants.default_conf_file)
    except:
        pass
    try:
        # Try to add the redhat_access_insights section
        parsedconfig.add_section(APP_NAME)
    except:
        pass
    return parsedconfig


def set_up_logging(config, verbose):
    """
    Initialize Logging
    """
    LOG_DIR = constants.log_dir
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR, 0700)
    logging_file = os.path.join(LOG_DIR, APP_NAME + '.log')

    valid_levels = ['ERROR', 'DEBUG', 'INFO', 'WARNING', 'CRITICAL']

    handler = logging.handlers.RotatingFileHandler(logging_file,
                                                   backupCount=3)

    # Send anything INFO+ to stdout and log
    stdout_handler = logging.StreamHandler(sys.stdout)
    if not verbose:
        stdout_handler.setLevel(logging.INFO)

    logging.root.addHandler(handler)
    logging.root.addHandler(stdout_handler)

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


def collect_data_and_upload(config, options):
    """
    All the heavy lifting done here
    """
    pconn = InsightsConnection(config)
    pconn.check_registration()
    branch_info = pconn.branch_info()
    pc = InsightsConfig(config, pconn)
    dc = DataCollector()
    logger.info('Collecting Insights data')
    start = time.clock()
    dynamic_config = pc.get_conf(options.update)
    elapsed = (time.clock() - start)
    logger.debug("Dynamic Config Elapsed Time: %s", elapsed)
    start = time.clock()
    dc.run_commands(dynamic_config)
    elapsed = (time.clock() - start)
    logger.debug("Command Collection Elapsed Time: %s", elapsed)
    start = time.clock()
    dc.copy_files(dynamic_config)
    elapsed = (time.clock() - start)
    logger.debug("File Collection Elapsed Time: %s", elapsed)
    dc.write_branch_info(branch_info)
    obfuscate = config.getboolean(APP_NAME, "obfuscate")

    if not options.no_tar_file:
        tar_file = dc.done(config, dynamic_config)
        if not options.no_upload:
            logger.info('Uploading Insights data,'
                        ' this may take a few minutes')
            pconn.upload_archive(tar_file)
            logger.info(
                'Check https://access.redhat.com/labs/insights in an hour')
            if not obfuscate and not options.keep_archive:
                dc.archive.delete_tmp_dir()
            else:
                if obfuscate:
                    logger.info('Obfuscated Insights data retained in %s',
                                os.path.dirname(tar_file))
                else:
                    logger.info('Insights data retained in %s', tar_file)
        else:
            logger.info('See Insights data in %s', tar_file)
    else:
        logger.info('See Insights data in %s', dc.archive.archive_dir)


def register(config, group_id=None):
    """
    Do registration using basic auth
    """
    username = config.get(APP_NAME, 'username')
    password = config.get(APP_NAME, 'password')
    if (((username == "") and
       (password == "") and
       (config.get(APP_NAME, 'authmethod') == 'BASIC')) and not
       (config.get(APP_NAME, 'auto_config'))):
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


def set_auto_configuration(config, hostname, ca_cert):
    """
    Set config based on discovered data
    """
    logger.debug("Attempting to auto conf %s %s %s", config, hostname, ca_cert)
    if ca_cert is not None:
        config.set(APP_NAME, 'cert_verify', ca_cert)
    config.set(APP_NAME, 'upload_url', 'https://' + hostname + '/rs/telemetry')
    config.set(
        APP_NAME, 'api_url', 'https://' + hostname + '/rs/telemetry/api')
    config.set(APP_NAME, 'branch_info_url', 'https://' +
               hostname + '/rs/telemetry/api/v1/branch_info')
    config.set(APP_NAME, 'dynamic_config_url', 'https://' +
               hostname + '/rs/telemetry/api/v1/static/uploader.json')


def _try_satellite6_configuration(config):
    """
    Try to autoconfigure for Satellite 6
    """
    try:
        from rhsm.config import initConfig
        RHSM_CONFIG = initConfig()

        logger.debug('Trying to autoconf Satellite 6')
        cert = file(rhsmCertificate.certpath(), 'r').read()
        key = file(rhsmCertificate.keypath(), 'r').read()
        rhsm = rhsmCertificate(key, cert)

        # This will throw an exception if we are not registered
        logger.debug('Checking if system is subscription-manager registered')
        rhsm.getConsumerId()
        logger.debug('System is subscription-manager registered')

        rhsm_hostname = RHSM_CONFIG.get('server', 'hostname')
        logger.debug("Found Satellite Server: %s", rhsm_hostname)
        rhsm_ca = RHSM_CONFIG.get('rhsm', 'repo_ca_cert')
        logger.debug("Found CA: %s", rhsm_ca)
        logger.debug("Setting authmethod to CERT")
        config.set(APP_NAME, 'authmethod', 'CERT')

        # Directly connected to Red Hat, use cert auth directly with the api
        if rhsm_hostname == 'subscription.rhn.redhat.com':
            logger.debug("Connected to RH Directly, using cert-api")
            rhsm_hostname = 'cert-api.access.redhat.com'
            rhsm_ca = None
        else:
            # Set the cert verify CA, and path
            rhsm_hostname = rhsm_hostname + '/redhat_access'

        logger.debug("Trying to set auto_configuration")
        set_auto_configuration(config, rhsm_hostname, rhsm_ca)
        return True
    except:
        logger.debug('System is NOT subscription-manager registered')
        return False


def _try_satellite5_configuration(config):
    """
    Attempt to determine Satellite 5 Configuration
    """
    logger.debug("Trying Satellite 5 auto_config")
    rhn_ca = '/usr/share/rhn/RHN-ORG-TRUSTED-SSL-CERT'
    rhn_config = '/etc/sysconfig/rhn/up2date'
    if os.path.isfile(rhn_ca) and os.path.isfile(rhn_config):
        logger.debug("Found Satellite 5 Certificate and Config")
        rhn_conf_file = file(rhn_config, 'r')
        hostname = None
        for line in rhn_conf_file:
            if line.startswith('serverURL='):
                from urlparse import urlparse
                url = urlparse(line.split('=')[1])
                hostname = url.netloc + '/redhat_access'
                logger.debug("Found hostname %s", hostname)

        if hostname:
            set_auto_configuration(config, hostname, rhn_ca)
        else:
            logger.debug("Could not find hostname")
            return False
        return True
    else:
        logger.debug("Could not find rhn config")
        return False


def try_auto_configuration(config):
    """
    Try to auto-configure if we are attached to a sat5/6
    """
    if not _try_satellite6_configuration(config):
        _try_satellite5_configuration(config)


def set_up_options(parser):
    """
    Add options to the option parser
    """
    parser.add_option('--register',
                      help=('Register system to Red Hat '
                            'Access Insights Support'),
                      action="store_true",
                      dest="register",
                      default=False)
    parser.add_option('--update',
                      help='Get new rules from Red Hat',
                      action="store_true",
                      dest="update",
                      default=False)
    parser.add_option('--validate',
                      help='Validate remove.json',
                      action="store_true",
                      dest="validate",
                      default=False)
    parser.add_option('--schedule',
                      help=("Set Red Hat Access Insights's schedule only "
                            "(no upload).  Must be used with --daily "
                            "or --weekly"),
                      action="store_true",
                      dest="schedule",
                      default=False)
    parser.add_option('--daily',
                      help=("Set Red Hat Access Insights "
                            "to collect data once per day"),
                      action="store_true",
                      dest="daily",
                      default=False)
    parser.add_option('--weekly',
                      help=("Set Red Hat Access Insights "
                            "to collect data once per week"),
                      action="store_true",
                      dest="weekly",
                      default=False)
    parser.add_option('--group',
                      action="store",
                      help='Group to add this system to during registration',
                      dest="group")
    parser.add_option('--satellite-group',
                      help=("Use this system's satellite "
                            "group during registration"),
                      action="store_true",
                      dest="satellite_group",
                      default=False)
    parser.add_option('--test-connection',
                      help='Test connectivity to Red Hat',
                      action="store_true",
                      dest="test_connection",
                      default=False)
    parser.add_option('--verbose',
                      help="DEBUG output to stdout",
                      action="store_true",
                      dest="verbose",
                      default=False)
    parser.add_option('--no-gpg',
                      help="Do not verify GPG signature",
                      action="store_true",
                      dest="no_gpg",
                      default=False)
    parser.add_option('--regenerate',
                      help="Regenerate machine-id",
                      action="store_true",
                      dest="regenerate",
                      default=False)
    parser.add_option('--no-upload',
                      help="Do not upload the archive",
                      action="store_true",
                      dest="no_upload",
                      default=False)
    parser.add_option('--no-tar-file',
                      help="Build the directory, but do not tar",
                      action="store_true",
                      dest="no_tar_file",
                      default=False)
    parser.add_option('--keep-archive',
                      help="Do not delete archive after upload",
                      action="store_true",
                      dest="keep_archive",
                      default=False)
    parser.add_option('--version',
                      help="Display version",
                      action="store_true",
                      dest="version",
                      default=False)


def _main():
    """
    Main entry point
    Parse cmdline options
    Parse config file
    Call data collector
    """
    global logger
    sys.excepthook = handle_exception

    parser = optparse.OptionParser()
    set_up_options(parser)
    options, args = parser.parse_args()
    if len(args) > 0:
        parser.error("Unknown arguments: %s" % args)
        sys.exit(1)

    if options.satellite_group and not options.register:
        parser.error("--satellite-group must be used with --register")

    if options.version:
        print constants.version
        sys.exit()

    if options.validate:
        validate_remove_file()
        sys.exit()

    if options.daily and options.weekly:
        parser.error("options --daily and --weekly are mutually exclusive")

    config = parse_config_file()
    logger, handler = set_up_logging(config, options.verbose)

    # Defer logging till it's ready
    logger.debug('invoked with args: %s', options)
    logger.debug("Version: " + constants.version)
    # Generate /etc/machine-id if it does not exist
    new = False
    if options.regenerate:
        new = True
    logger.debug("Machine-ID: " + generate_machine_id(new))

    # Disable GPG verification
    if options.no_gpg:
        logger.warn("GPG VERIFICATION DISABLED")
        config.set(APP_NAME, 'gpg', 'False')

    # Log config except the password
    # and proxy as it might have a pw as well
    for item, value in config.items(APP_NAME):
        if item != 'password' and item != 'proxy':
            logger.debug("%s:%s",  item, value)

    if config.getboolean(APP_NAME, 'auto_update'):
        options.update = True

    if config.getboolean(APP_NAME, 'auto_config'):
        # Try to discover if we are connected to a satellite or not
        try_auto_configuration(config)

    # Set the schedule
    InsightsSchedule(options)

    # Test connection, useful for proxy debug
    if options.test_connection:
        pconn = InsightsConnection(config)
        pconn._test_connection()

    # Handle registration and grouping, this is mostly a no-op
    if options.register:
        opt_group = options.group
        if options.satellite_group:
            opt_group = get_satellite_group()
        hostname, opt_group = register(config, opt_group)
        logger.info('Successfully registered %s in group %s', hostname, opt_group)

    # Check for .unregistered file
    if os.path.isfile(constants.unregistered_file):
        logger.error("This machine has been unregistered")
        logger.error("Use --register if you would like to re-register this machine")
        logger.error("Exiting")
        sys.exit(1)

    # If we are not just setting the schedule, do work son
    if not options.schedule:
        collect_data_and_upload(config, options)
        handler.doRollover()

if __name__ == '__main__':
    _main()
