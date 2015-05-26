"""
Rules for data collection
"""
import json
import logging
import sys
import six
import shlex
import os
from subprocess import Popen, PIPE, STDOUT
from tempfile import NamedTemporaryFile
from constants import InsightsConstants as constants

APP_NAME = constants.app_name
logger = logging.getLogger(APP_NAME)


class InsightsConfig(object):
    """
    Insights configuration
    """

    def __init__(self, config, conn):
        """
        Load config from parent
        """
        self.fallback_file = constants.collection_fallback_file
        self.remove_file = constants.collection_remove_file
        self.collection_rules_file = constants.collection_rules_file
        self.base_url = 'https://' + config.get(APP_NAME, 'base_url')
        self.collection_rules_url = config.get(APP_NAME, 'collection_rules_url')
        if self.collection_rules_url is None:
            self.collection_rules_url = self.base_url + '/v1/static/uploader.json'
        self.gpg = config.getboolean(APP_NAME, 'gpg')
        self.conn = conn

    def validate_gpg_sig(self, path, sig=None):
        """
        Validate the collection rules
        """
        logger.info("Verifying GPG signature of Insights configuration")
        if sig is None:
            sig = path + ".asc"
        command = ("/usr/bin/gpg --no-default-keyring "
                   "--keyring " + constants.pub_gpg_path +
                   " --verify " + sig + " " + path)
        if not six.PY3:
            command = command.encode('utf-8', 'ignore')
        args = shlex.split(command)
        logger.debug("Executing: %s", args)
        proc = Popen(
            args, shell=False, stdout=PIPE, stderr=STDOUT, close_fds=True)
        stdout, stderr = proc.communicate()
        logger.debug("STDOUT: %s", stdout)
        logger.debug("STDERR: %s", stderr)
        logger.debug("Status: %s", proc.returncode)
        if proc.returncode:
            sys.exit("ERROR: Unable to validate GPG signature! Exiting!")
        else:
            logger.debug("GPG signature verified")
            return True

    def try_disk(self, path, gpg=True):
        """
        Try to load json off disk
        """
        if not os.path.isfile(path):
            return

        if not gpg or self.validate_gpg_sig(path):
            stream = open(path, 'r')
            json_stream = stream.read()
            if len(json_stream):
                try:
                    json_config = json.loads(json_stream)
                    return json_config
                except ValueError:
                    logger.error("ERROR: Invalid JSON in %s", path)
                    sys.exit(1)
            else:
                logger.warn("WARNING: %s was an empty file", path)
                return

    def get_conf(self, update):
        """
        Get the config
        """
        rm_conf = None
        # Convert config object into dict
        if os.path.isfile(self.remove_file):
            from ConfigParser import RawConfigParser
            parsedconfig = RawConfigParser()
            parsedconfig.read(self.remove_file)
            rm_conf = {}
            for item, value in parsedconfig.items('remove'):
                    rm_conf[item] = value.strip().split(',')
            try:
                patterns = rm_conf['patterns']
                logger.warn("WARNING: Excluding data from files")
            except LookupError:
                pass

        if update:
            logger.info("Attemping to download collection rules from %s",
                        self.collection_rules_url)

            req = self.conn.session.get(
                self.collection_rules_url, headers=({'accept': 'text/plain'}))

            logger.info("Attemping to download collection "
                        "rules GPG signature from %s",
                        self.collection_rules_url + ".asc")

            headers = ({'accept': 'text/plain'})
            config_sig = self.conn.session.get(self.collection_rules_url + '.asc',
                                               headers=headers)

            if req.status_code == 200 and config_sig.status_code == 200:
                logger.info("Successfully downloaded collection "
                            "rules and GPG signature")

                json_response = NamedTemporaryFile()
                json_response.write(req.text)
                json_response.file.flush()
                sig_response = NamedTemporaryFile(suffix=".asc")
                sig_response.write(config_sig.text)
                sig_response.file.flush()
                self.validate_gpg_sig(json_response.name, sig_response.name)

                dyn_conf = json.loads(req.text)
                # Ensure that we have JSON
                if dyn_conf:
                    try:
                        dyn_conf['version']
                        dyn_conf_file = os.fdopen(os.open(self.collection_rules_file,
                                                          os.O_WRONLY | os.O_CREAT,
                                                          int("0600", 8)), 'w')
                        dyn_conf_file.write(req.text)
                        dyn_conf_file.close()
                        dyn_conf_sig_file = os.fdopen(os.open(self.collection_rules_file + ".asc",
                                                              os.O_WRONLY | os.O_CREAT,
                                                              int("0600", 8)), 'w')
                        dyn_conf_sig_file.write(config_sig.text)
                        dyn_conf_sig_file.close()
                        dyn_conf['file'] = self.collection_rules_file
                        logger.debug("Success reading config")
                        logger.debug(json.dumps(dyn_conf))
                        return dyn_conf, rm_conf
                    except LookupError:
                        logger.error("ERROR: Could not parse json from remote host")
            else:
                logger.error("ERROR: Could not download dyanmic configuration")
                logger.error("Debug Info: \nConf status: %s", req.status_code)
                logger.error("Sig status: %s", config_sig.status_code)

        for conf_file in [self.collection_rules_file, self.fallback_file]:
            logger.debug("trying to read conf from: " + conf_file)
            conf = self.try_disk(conf_file, self.gpg)
            if conf:
                try:
                    conf['version']
                    conf['file'] = conf_file
                    logger.debug("Success reading config")
                    logger.debug(json.dumps(conf))
                    return conf, rm_conf
                except LookupError:
                    logger.debug("Failed to find version")

        logger.error("ERROR: Unable to download conf or read it from disk!")
        sys.exit()
