'''
Functions to handle upload
'''
import json
import os
import shutil
import sys
import time
import atexit
import logging
from utilities import write_lastupload_file, determine_hostname
from collection_rules import InsightsConfig
from data_collector import DataCollector
from connection import InsightsConnection
from archive import InsightsArchive
from constants import InsightsConstants as constants
from container_utils import open_image, force_clean, unmount_obj

APP_NAME = constants.app_name
logger = logging.getLogger(APP_NAME)


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


def collect_data_and_upload(config, options, rc=0, targets=constants.default_target):
    """
    All the heavy lifting done here
    Run through "targets" - could be just one (host, default) or many (containers+host)
    """
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

    stdin_config = json.load(sys.stdin) if options.from_stdin else {}

    start = time.clock()
    collection_rules, rm_conf = pc.get_conf(options.update, stdin_config)
    collection_elapsed = (time.clock() - start)
    logger.debug("Collection Rules Elapsed Time: %s", collection_elapsed)

    for t in targets:
        # default mountpoint to None
        mp = None
        # mount if target is an image
        if t['type'] is 'image':
            mounted_image = open_image(t['name'])
            mp = mounted_image.mount_point
            # unmount on unexpected exit
            atexit.register(unmount_on_exit, mounted_image)

        collection_start = time.clock()

        # new archive for each container
        archive = InsightsArchive(compressor=options.compressor, container_name=t['name'])
        dc = DataCollector(archive, mountpoint=mp, container_name=t['name'])

        # register the exit handler here to delete the archive
        atexit.register(handle_exit, archive, options.keep_archive or options.no_upload)

        start = time.clock()
        logger.info('Starting to collect Insights data for %s' % (determine_hostname() if t['name'] is None else t['name']))
        dc.run_commands(collection_rules, rm_conf)
        elapsed = (time.clock() - start)
        logger.debug("Command Collection Elapsed Time: %s", elapsed)

        start = time.clock()
        dc.copy_files(collection_rules, rm_conf)
        elapsed = (time.clock() - start)
        logger.debug("File Collection Elapsed Time: %s", elapsed)

        dc.write_branch_info(branch_info)
        obfuscate = config.getboolean(APP_NAME, "obfuscate")

        # include rule refresh time in the duration
        collection_duration = (time.clock() - collection_start) + collection_elapsed

        # unmount image when we are finished
        if t['type'] is 'image':
            unmount_obj(mounted_image.client, mp, mounted_image.cid)

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


def handle_exit(archive, keep_archive):
    # delete the archive on exit so we don't keep crap around
    if not keep_archive:
        archive.delete_tmp_dir()


def unmount_on_exit(container):
    try:
        force_clean(container.client, container.cid, container.mount_point)
    except:
        # it was already unmounted
        pass
