import pytest
<<<<<<< 28ace100269339739607e7c9d5a57fc9f967f688
import subprocess
import logging
import os
import sys
import re
import fileinput
from subprocess import Popen, PIPE
=======
import subprocess, logging
import os, sys, re
from insights_client.constants import InsightsConstants as constants

if os.path.isfile(constants.default_log_file):
    os.system("mv " + constants.default_log_file + " "  + constants.default_log_file + ".backup")
>>>>>>> added a few more tests and fixed file backup issues

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format='%(asctime)s %(message)s')
mylogger = logging.getLogger()

<<<<<<< 28ace100269339739607e7c9d5a57fc9f967f688

def test_option_daily_check():
    subprocess.call(['redhat-access-insights --schedule --daily'], shell=True)
    if os.path.isfile("/etc/cron.daily/redhat-access-insights"):
        mylogger.debug("cron job set to daily - VERIFIED")
    else:
        pytest.fail("Cron job not set to daily")


def test_option_weekly_check():
    subprocess.call(['redhat-access-insights --schedule --weekly'], shell=True)
    if os.path.isfile("/etc/cron.weekly/redhat-access-insights"):
        mylogger.debug("Cron job set to weekly - VERIFIED")
        pass
=======
def test_unregister():
    unregister = subprocess.Popen([constants.app_name + " --unregister"], stdout=subprocess.PIPE, shell=True)
    unregister_output, err = unregister.communicate()
    print unregister_output
    if re.search("Successfully unregistered", unregister_output)  is not None:
        pass
    else:
        print err
        pytest.fail("System was not unregistered")

def test_register():
    register = subprocess.Popen([constants.app_name + " --register"], stdout=subprocess.PIPE, shell=True)
    register_output, err = register.communicate()
    print register_output
    if (re.search("Successfully registered", register_output) or re.search("already been registerd", register_output)) is not None:
        pass
    else:
        print err
        pytest.fail("System was not registered")

def test_option_disable_schedule():
    if os.path.isfile("/etc/cron.daily/" + constants.app_name):
        os.system("cp /etc/cron.daily/" + constants.app_name + " /etc/cron.daily/" + constants.app_name + ".backup")
    subprocess.call([constants.app_name + " --disable-schedule"], shell=True)
    if os.path.isfile("/etc/cron.daily/" + constants.app_name):
        pytest.fail("Cron job daily schedule not disabled")
        os.system("rm -f /etc/cron.daily/" + constants.app_name)
    else:
        with open(constants.default_conf_file, "r") as f:
            flagSet = False
            for line in f:
                if "no_schedule=True" in line:
                    flagSet = True
            if flagSet:
                mylogger.debug("Cron job daily schedule disabled - VERIFIED")
            else:
                pytest.fail("Cron job daily schedule not disabled")

    if os.path.isfile("/etc/cron.daily/" + constants.app_name + ".backup"):
        os.system("mv /etc/cron.daily/" + constants.app_name + ".backup /etc/cron.daily/" + constants.app_name)

def test_option_enable_schedule():
    if os.path.isfile("/etc/cron.daily/" + constants.app_name):
        os.system("mv /etc/cron.daily/" + constants.app_name + " /etc/cron.daily/" + constants.app_name + ".backup")
    subprocess.call([constants.app_name + " --enable-schedule"], shell=True)
    if os.path.isfile("/etc/cron.daily/" + constants.app_name):
        os.system("rm -f /etc/cron.daily/" + constants.app_name)
        with open(constants.default_conf_file, "r") as f:
            flagSet = False
            for line in f:
                if "no_schedule=False" in line:
                    flagSet = True
            if flagSet:
                mylogger.debug("Cron job daily schedule enabled - VERIFIED")
            else:
                pytest.fail("Cron job daily schedule not enabled")
>>>>>>> added a few more tests and fixed file backup issues
    else:
        pytest.fail("Cron job not set to weekly")


    if os.path.isfile("/etc/cron.daily/" + constants.app_name + ".backup"):
        os.system("mv /etc/cron.daily/" + constants.app_name + ".backup /etc/cron.daily/" + constants.app_name)

def test_gpg_verification_check():
    check_gpg = subprocess.Popen(["redhat-access-insights"], stdout=subprocess.PIPE, shell=True)
    gpg_check_text, err = check_gpg.communicate()
    var = re.compile(r".*Upload completed successfully.*")
    if re.search(var, gpg_check_text) is not None:
        pass
        mylogger.debug("GPG verification - VERIFIED")
    else:
        print gpg_check_text, err
        pytest.fail("GPG verification not done")

    try:
        mylogger.debug("checking if the gpg check fails on modifying .cache.json")
        os.system("cp /etc/redhat-access-insights/.cache.json /etc/redhat-access-insights/.cache.json.backup")
        with open("/etc/redhat-access-insights/.cache.json", "a") as f:
            f.write("#changing .cache.json")

        os.system("cp /etc/redhat-access-insights/redhat-access-insights.conf /etc/redhat-access-insights/redhat-access-insights.conf.backup")
        with open("/etc/redhat-access-insights/redhat-access-insights.conf", "r") as f:
            auto_update_change = f.read().replace("#auto_update=True", "auto_update=False")
        with open("/etc/redhat-access-insights/redhat-access-insights.conf", "w") as f:
            f.write(auto_update_change)

        gpg = subprocess.Popen(["redhat-access-insights"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        gpg_output, gpg_err = gpg.communicate()
        gpg_regex = re.compile(r".*Unable to validate gpg signature.*")
        print "Console output:"
        print gpg_err
        if re.search(gpg_regex, gpg_err) is not None:
            pass
            print "Upload must fail if gpg signature not verified - VERIFIED"
        else:
            pytest.fail("should not be able to upload successfully without gpg verification")

    except Exception as e:
        print e
        os.system("rm /etc/redhat-access-insights/.cache.json")
        os.system("mv /etc/redhat-access-insights/.cache.json.backup /etc/redhat-access-insights/.cache.json")
        os.system("rm /etc/redhat-access-insights/redhat-access-insights.conf")
        os.system("mv /etc/redhat-access-insights/redhat-access-insights.conf.backup /etc/redhat-access-insights/redhat-access-insights.conf")
        print "reverted changes made to .cache.json and redhat-access-insights.conf"
        pytest.fail("should not be able to upload successfully without gpg verification")

    os.system("rm /etc/redhat-access-insights/.cache.json")
    os.system("mv /etc/redhat-access-insights/.cache.json.backup /etc/redhat-access-insights/.cache.json")
    print "Reverting changes made to /etc/redhat-access-insights/.cache.json and /etc/redhat-access-insights/redhat-access-insights.conf"
    os.system("rm /etc/redhat-access-insights/redhat-access-insights.conf")
    os.system("mv /etc/redhat-access-insights/redhat-access-insights.conf.backup /etc/redhat-access-insights/redhat-access-insights.conf")


def test_gpg_verification_disabled_check():
    gpg_disabled = subprocess.Popen(["redhat-access-insights --no-gpg"], stdout=subprocess.PIPE, shell=True)
    gpg_check_text, err = gpg_disabled.communicate()
    if re.search("GPG VERIFICATION DISABLED", gpg_check_text) is not None:
        pass
        mylogger.debug("--no-gpg option disables gpg verification successfully")
    else:
        pytest.fail("--no-gpg was not able to disable gpg verification")


def test_blacklist_functionality_with_keep_archive():
<<<<<<< 28ace100269339739607e7c9d5a57fc9f967f688
    if os.path.isfile("/etc/redhat-access-insights/remove.json"):
        os.system("rm /etc/redhat-access-insights/remove.json")
    os.system("cp ./tests/data/remove.json /etc/redhat-access-insights/")
    if os.path.isfile("/etc/redhat-access-insights/remove.json"):
        remove_json = subprocess.Popen(["redhat-access-insights --keep-archive"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, err = remove_json.communicate()
=======
    if os.path.isfile(constants.collection_remove_file):
        os.system("mv " + constants.collection_remove_file + " " + constants.collection_remove_file + ".backup")
        os.system("cp ./tests/data/" + constants.collection_remove_file_name + " " + constants.collection_remove_file)
    if os.path.isfile(constants.collection_remove_file):
        remove_conf = subprocess.Popen([constants.app_name + " --keep-archive"], stdout=subprocess.PIPE,stderr=subprocess.PIPE, shell=True)
        output, err = remove_conf.communicate()
>>>>>>> added a few more tests and fixed file backup issues
        print output
        archive_regex = re.compile(r"Insights data retained in /var/tmp/.*")
        archive_dir = re.search(archive_regex, output)
        dir_archived = archive_dir.group(0).split("in ")[1]
        archive_name = dir_archived.split("/")[-1]
        print archive_name
        os.system("tar -xf %s -C /tmp" % dir_archived)
        archive_directory = archive_name.split(".tar")[0]

<<<<<<< 28ace100269339739607e7c9d5a57fc9f967f688
        if os.path.isfile("/tmp/%s/insights_commands/lspci" % archive_directory):
            pytest.fail("The command '/sbin/lspci' in the remove.json did not get blacklisted")
=======
        os.system("rm " + constants.collection_remove_file);
        if os.path.isfile(constants.collection_remove_file + ".backup"):
            os.system("mv " + constants.collection_remove_file + ".backup " + constants.collection_remove_file)

        if os.path.isfile("/tmp/%s/insights_commands/lspci" %archive_directory):
            pytest.fail("The command '/sbin/lspci' in the " + constants.collection_remove_file_name + " did not get blacklisted")
>>>>>>> added a few more tests and fixed file backup issues
        else:
            print "The command '/sbin/lspci' from remove.json got blacklisted(not executed) - VERIFIED"
        print "Files in the archived dir:"
        print os.system("cd /tmp/%s/etc;ls" % archive_directory)
        if os.path.isfile("/tmp/%s/etc/hosts" % archive_directory):
            pytest.fail("The file 'etc/ssh/hosts' from remove.json did not get blacklisted")
        else:
            print "The file 'etc/hosts from remove.json got blacklisted - VERIFIED"
        os.system("rm -rf /tmp/%s" % archive_directory)
        print "deleting archived dir in /tmp/%s" % archive_directory


def test_machine_id_verification():
    if os.path.isfile("/etc/redhat-access-insights/machine-id"):
        machine_id = subprocess.Popen(["cat /etc/redhat-access-insights/machine-id"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        machineid, err = machine_id.communicate()
        print "\n'/etc/redhat-access-insights/machine-id' is present as: %s" % machineid
    else:
        pytest.fail("'/etc/redhat-access-insights/machine-id' is not present")
        print err


def test_no_upload_option():
    no_upload = subprocess.Popen(["redhat-access-insights --no-upload"], stdout=subprocess.PIPE, shell=True)
    no_upload_output, err = no_upload.communicate()
    print no_upload_output
    tar_regex = re.compile(r".*tar\.gz.*")
    if re.search(tar_regex, no_upload_output) is not None and re.search("Upload completed successully!", no_upload_output) is None:
        tar_file = no_upload_output.split("See Insights data in ")[1]
        print tar_file
    else:
        print err
        pytest.fail("The upload was successfull despite of the option --no-upload")

    os.system("rm -rf  /var/tmp/%s" % tar_file.split("/")[3])
    print "Deleted tar file %s" % tar_file


def test_no_tar_file_option():
    no_tar_file = subprocess.Popen(["redhat-access-insights --no-tar-file"], stdout=subprocess.PIPE, shell=True)
    no_tar_output, err = no_tar_file.communicate()
    print no_tar_output
    tar_regex = re.compile(r".*tar\.gz.*")
    if re.search(tar_regex, no_tar_output) is None and re.search("Upload completed successully!", no_tar_output) is None:
        no_tar_dir = no_tar_output.split("See Insights data in ")[1]
        print no_tar_dir
    else:
        print err
        pytest.fail("The tar file should not have been created with usage of option --no-tar-file")

    os.system("rm -rf  /var/tmp/%s" % no_tar_dir.split("/")[3])
<<<<<<< 28ace100269339739607e7c9d5a57fc9f967f688
    print "Deleted tar file %s" % no_tar_dir
=======
    print "Deleted tar file %s" %no_tar_dir

def test_support_option():
    if os.path.isfile(constants.default_log_file):
        os.system("mv " + constants.default_log_file + " "  + constants.default_log_file + ".backup1")
    subprocess.call([constants.app_name + " --support"], shell=True)
    if os.path.isfile(constants.default_log_file):
        os.system("rm -f  " + constants.default_log_file)
        os.system("mv " + constants.default_log_file + ".backup1 "  + constants.default_log_file)
        print "\n'" + constants.default_log_file + "' was created"
    else:
        pytest.fail("'" + constants.default_log_file + "' was not created")

def test_version_option():
    version = subprocess.Popen([constants.app_name + " --version"], stdout=subprocess.PIPE, shell=True)
    version_output, err = version.communicate()
    print version_output
    version_regex = re.compile(r"[0-9]\.[0-9]\.[0-9]")
    if re.search(version_regex, version_output) is not None:
        pass
    else:
        print err
        pytest.fail("Did not print version number")

def test_update_collection_rules():
    update_collection = subprocess.Popen([constants.app_name + " --update-collection-rules"], stdout=subprocess.PIPE, shell=True)
    update_output, err = update_collection.communicate()
    print update_output
    if re.search("Upload completed successfully", update_output) is not None:
        pass
    else:
        print err
        pytest.fail("Collection rules were not updated")

def test_compressor_option():
    compressor = subprocess.Popen([constants.app_name + " --compressor=bzip2 --no-upload"], stdout=subprocess.PIPE, shell=True)
    compressor_output, err = compressor.communicate()
    print compressor_output
    compressor_regex = re.compile(r".*tar\.bzip2.*")
    if re.search(compressor_regex, compressor_output) is not None and re.search("Upload completed successully!", compressor_output) is None:
        tar_file = compressor_output.split("See Insights data in ")[1]
        print tar_file
    else:
        print err
        pytest.fail("The upload was successfull despite of the option --no-upload")

    os.system("rm -rf  /var/tmp/%s" % tar_file.split("/")[3])
    print "Deleted tar file %s" %tar_file





# TODO Finish this
# def test_custom_config():
    # fail
    # subprocess.call([constants.app_name + " --conf=./test/data/test_custom.conf"], shell=True)
    # if os.path.isfile("/etc/cron.daily/" + constants.app_name):
        # with open(constants.default_conf_file, "r") as f:
            # flagSet = False
            # for line in f:
                # if "no_schedule=False" in line:
                    # flagSet = True
            # if flagSet:
                # mylogger.debug("Cron job daily schedule enabled - VERIFIED")
            # else:
                # pytest.fail("Cron job daily schedule not enabled")
    # else:
        # pytest.fail("Cron job not set to daily schedule")
>>>>>>> added a few more tests and fixed file backup issues
