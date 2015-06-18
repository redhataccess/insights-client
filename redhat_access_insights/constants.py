"""
Constants
"""


class InsightsConstants(object):
    app_name = 'redhat-access-insights'
    version = '1.0.5'
    auth_method = 'BASIC'
    log_level = 'DEBUG'
    sleep_time = 300
    user_agent = app_name + '/' + version
    default_conf_dir = '/etc/' + app_name + '/'
    log_dir = '/var/log/' + app_name
    default_log_file = log_dir + '/' + app_name + '.log'
    default_conf_file = default_conf_dir + app_name + '.conf'
    default_sed_file = default_conf_dir + '.exp.sed'
    default_ca_file = default_conf_dir + 'cert-api.access.redhat.com.pem'
    base_url = 'cert-api.access.redhat.com/r/insights'
    collection_rules_file = default_conf_dir + '.cache.json'
    collection_fallback_file = default_conf_dir + '.fallback.json'
    collection_remove_file = default_conf_dir + 'remove.conf'
    unregistered_file = default_conf_dir + '.unregistered'
    registered_file = default_conf_dir + '.registered'
    pub_gpg_path = default_conf_dir + 'redhattools.pub.gpg'
    machine_id_file = default_conf_dir + 'machine-id'
