"""
Utility functions
"""
import socket
import shlex
import os
import sys
import logging
import uuid
import json
from subprocess import Popen, PIPE
from constants import InsightsConstants as constants

logger = logging.getLogger(constants.app_name)


def determine_hostname():
    """
    Find fqdn if we can
    """
    socket_gethostname = socket.gethostname()
    socket_fqdn = socket.getfqdn()

    try:
        socket_ex = socket.gethostbyname_ex(socket_gethostname)[0]
    except LookupError:
        socket_ex = ''

    gethostname_len = len(socket_gethostname)
    fqdn_len = len(socket_fqdn)
    ex_len = len(socket_ex)

    if fqdn_len > gethostname_len or ex_len > gethostname_len:
        if "localhost" not in socket_ex:
            return socket_ex
        if "localhost" not in socket_fqdn:
            return socket_fqdn

    return socket_gethostname


def get_satellite_group():
    """
    Obtain satellite group name
    """
    cmd = '/usr/sbin/subscription-manager identity'
    args = shlex.split(cmd)
    proc1 = Popen(args, stdout=PIPE)
    proc2 = Popen(["/bin/grep", 'org name'],
                  stdin=proc1.stdout,
                  stdout=PIPE)
    # Find org name and grab the name from the end
    sat_group = proc2.communicate()[0].strip().split().pop()
    logger.debug("Satellite Group: %s", sat_group)
    return sat_group


def _write_machine_id(machine_id):
    """
    Write machine id out to disk
    """
    logger.debug("Creating %s", constants.machine_id_file)
    machine_id_file = open(constants.machine_id_file, "w")
    machine_id_file.write(machine_id)
    machine_id_file.flush()
    machine_id_file.close()


def write_unregistered_file(date):
    """
    Write .unregistered out to disk
    """
    unreg = file(constants.unregistered_file, 'w')
    unreg.write(str(date))
    logger.error("This machine has been unregistered")
    logger.error("Use --register if you would like to re-register this machine")
    logger.error("Exiting")
    sys.exit(1)


def delete_unregistered_file():
    """
    Remove the .unregistered file if we are doing a register
    """
    if os.path.isfile(constants.unregistered_file):
        os.remove(constants.unregistered_file)


def generate_machine_id(new=False):
    """
    Generate a machine-id if /etc/machine-id does not exist
    """
    machine_id = None
    machine_id_file = None
    if os.path.isfile(constants.machine_id_file) and not new:
        logger.debug('Found %s', constants.machine_id_file)
        machine_id_file = open(constants.machine_id_file, 'r')
        machine_id = machine_id_file.read()
        machine_id_file.close()
    elif (os.path.isfile('/etc/machine-id') and not
          os.path.isfile(constants.machine_id_file)):
        logger.debug('Found /etc/machine-id, '
                     'but not %s', constants.machine_id_file)
        machine_id_file = open("/etc/machine-id", "r")
        machine_id = machine_id_file.read()
        machine_id_file.close()
        _write_machine_id(machine_id)
    elif ((not os.path.isfile('/etc/machine-id')
           and not os.path.isfile(constants.machine_id_file))
          or new):
        logger.debug('Could not find machine-id file, creating')
        machine_id = str(uuid.uuid4())
        _write_machine_id(machine_id)
    return str(machine_id).strip()


def generate_dmidecode():
    """
    Generate a machine_id based off dmidecode fields
    """
    import hashlib
    import dmidecode
    dmixml = dmidecode.dmidecodeXML()

    # Fetch all DMI data into a libxml2.xmlDoc object
    dmixml.SetResultType(dmidecode.DMIXML_DOC)
    xmldoc = dmixml.QuerySection('all')

    # Do some XPath queries on the XML document
    dmixp = xmldoc.xpathNewContext()

    # What to look for - XPath expressions
    keys = ['/dmidecode/SystemInfo/Manufacturer',
            '/dmidecode/SystemInfo/ProductName',
            '/dmidecode/SystemInfo/SerialNumber',
            '/dmidecode/SystemInfo/SystemUUID']

    # Create a sha256 of ^ for machine_id
    machine_id = hashlib.sha256()

    # Run xpath expressions
    for k in keys:
        data = dmixp.xpathEval(k)
        for element in  data:
            logger.log(logging.DEBUG, "%s: %s", k, element.get_content())
            # Update the hash as we find the fields we are looking for
            machine_id.update(element.get_content())

    del dmixp
    del xmldoc
    # Create sha256 digest
    return machine_id.hexdigest()


def _expand_paths(path):
    """
    Expand wildcarded paths
    """
    import re
    dir_name = os.path.dirname(path)
    paths = []
    logger.debug("Attempting to expand %s", path)
    if os.path.isdir(dir_name):
        files = os.listdir(dir_name)
        match = os.path.basename(path)
        for file_path in files:
            if re.match(match, file_path):
                expanded_path = os.path.join(dir_name, file_path)
                paths.append(expanded_path)
        logger.debug("Expanded paths %s", paths)
        return paths
    else:
        logger.debug("Could not expand %s", path)


def write_file_with_text(path, text):
    """
    Write to file with text
    """
    try:
        os.makedirs(os.path.dirname(path))
    except OSError:
        logger.debug("Could not create dir for %s", os.path.dirname(path))

    file_from_text = open(path, 'w')
    file_from_text.write(text.encode('utf8'))
    file_from_text.close()


def validate_remove_file():
    """
    Validate the remove file
    """
    import stat
    # Make sure permissions are 600
    mode = stat.S_IMODE(os.stat(constants.dynamic_remove_file).st_mode)
    if not mode == 0o600:
        sys.exit("Invalid remove file permissions"
                 "Expected 0600 got %s" % oct(mode))
    else:
        logger.info("Correct file permissions")

    rem_json = json.loads(file(constants.dynamic_remove_file, 'r').read())
    print json.dumps(rem_json, sort_keys=True, indent=4, separators=(',', ': '))
    logger.info("JSON parsed correctly")
