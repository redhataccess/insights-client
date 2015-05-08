"""
Auto Configuration Helper
"""
import logging
import os
from constants import InsightsConstants as constants
from cert_auth import rhsmCertificate

logger = logging.getLogger(constants.app_name)

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
