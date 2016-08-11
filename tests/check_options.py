import pytest
import subprocess, logging
import os, sys, re
from insights_client.constants import InsightsConstants as constants

if os.path.isfile(constants.default_log_file):
    os.system("mv " + constants.default_log_file + " "  + constants.default_log_file + ".backup")

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format='%(asctime)s %(message)s')
mylogger = logging.getLogger()

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
                print "Cron job daily schedule disabled - VERIFIED"
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
                print "Cron job daily schedule enabled - VERIFIED"
            else:
                pytest.fail("Cron job daily schedule not enabled")
    else:
        pytest.fail("Cron job daily schedule not enabled")

    if os.path.isfile("/etc/cron.daily/" + constants.app_name + ".backup"):
        os.system("mv /etc/cron.daily/" + constants.app_name + ".backup /etc/cron.daily/" + constants.app_name)

def test_gpg_verification_check():
    check_gpg = subprocess.Popen([constants.app_name], stdout=subprocess.PIPE, shell=True)
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
        os.system("cp " + os.path.join(constants.default_conf_dir, ".cache.json") + " " + os.path.join(constants.default_conf_dir, ".cache.json.backup"))
        with open(os.path.join(constants.default_conf_dir , ".cache.json"), "a") as f:
            f.write("#changing .cache.json")

        os.system("cp " + constants.default_conf_file + " " + constants.default_conf_file + ".backup")
        with open(constants.default_conf_file, "r") as f:
            auto_update_change = f.read().replace("#auto_update=True","auto_update=False")
        with open(constants.default_conf_file, "w") as f:
            f.write(auto_update_change)

        gpg = subprocess.Popen([constants.app_name], stdout=subprocess.PIPE,stderr=subprocess.PIPE, shell=True)
        gpg_output, gpg_err = gpg.communicate()
        gpg_regex = re.compile(r".*Unable to validate GPG signature.*")
        print "Console output:"
        print gpg_err
        if re.search(gpg_regex, gpg_err) is not None:
            pass
            print "Upload must fail if gpg signature not verified - VERIFIED"
        else:
            pytest.fail("should not be able to upload successfully without gpg verification")

    except Exception as e:
        print e
        os.system("rm " + os.path.join(constants.default_conf_dir, ".cache.json"))
        os.system("mv " + os.path.join(constants.default_conf_dir, ".cache.json.backup") + " " + os.path.join(constants.default_conf_dir, ".cache.json"))
        os.system("rm " + constants.default_conf_file)
        os.system("mv " + constants.default_conf_file + ".backup " + constants.default_conf_file)
        print "reverted changes made to .cache.json and " + constants.default_conf_file_name
        pytest.fail("should not be able to upload successfully without gpg verification")

    os.system("rm " + os.path.join(constants.default_conf_dir, ".cache.json"))
    os.system("mv " + os.path.join(constants.default_conf_dir, ".cache.json.backup") + " " + os.path.join(constants.default_conf_dir, ".cache.json"))
    print "Reverting changes made to " + constants.default_conf_dir + ".cache.json and " + constants.default_conf_file
    os.system("rm " + constants.default_conf_file)
    os.system("mv " + constants.default_conf_file + ".backup " + constants.default_conf_file)

def test_gpg_verification_disabled_check():
    gpg_disabled = subprocess.Popen([constants.app_name + " --no-gpg"], stdout=subprocess.PIPE, shell=True)
    gpg_check_text, err = gpg_disabled.communicate()
    if re.search("GPG VERIFICATION DISABLED", gpg_check_text) is not None:
        pass
        mylogger.debug("--no-gpg option disables gpg verification successfully")
    else:
        pytest.fail("--no-gpg was not able to disable gpg verification")

def test_blacklist_functionality_with_keep_archive():
    if os.path.isfile(constants.collection_remove_file):
        os.system("mv " + constants.collection_remove_file + " " + constants.collection_remove_file + ".backup")
    os.system("cp ./tests/data/" + constants.collection_remove_file_name + " " + constants.collection_remove_file)

    remove_conf = subprocess.Popen([constants.app_name + " --keep-archive"], stdout=subprocess.PIPE,stderr=subprocess.PIPE, shell=True)
    output, err = remove_conf.communicate()
    print output
    archive_regex = re.compile(r"Insights data retained in /var/tmp/.*")
    archive_dir = re.search(archive_regex, output)
    dir_archived = archive_dir.group(0).split("in ")[1]
    archive_name =  dir_archived.split("/")[-1]
    print archive_name
    os.system("tar -xf %s -C /tmp" % dir_archived)
    archive_directory = archive_name.split(".tar")[0]

    os.system("rm " + constants.collection_remove_file)
    if os.path.isfile(constants.collection_remove_file + ".backup"):
        os.system("mv " + constants.collection_remove_file + ".backup " + constants.collection_remove_file)

    if os.path.isfile("/tmp/%s/insights_commands/lspci" %archive_directory):
        pytest.fail("The command '/sbin/lspci' in the " + constants.collection_remove_file_name + " did not get blacklisted")
    else:
        print "The command '/sbin/lspci' from " + constants.collection_remove_file_name + " got blacklisted(not executed) - VERIFIED"
    print "Files in the archived dir:"
    print os.system("cd /tmp/%s/etc;ls" % archive_directory)
    if os.path.isfile("/tmp/%s/etc/hosts" %archive_directory ):
        pytest.fail("The file 'etc/ssh/hosts' from " + constants.collection_remove_file_name + " did not get blacklisted")
    else:
        print "The file 'etc/hosts from " + constants.collection_remove_file_name + " got blacklisted - VERIFIED"
    os.system("rm -rf /tmp/%s" %archive_directory)
    print "deleting archived dir in /tmp/%s" %archive_directory

def test_machine_id_verification():
    if os.path.isfile(constants.machine_id_file):
        machine_id = subprocess.Popen(["cat " + constants.machine_id_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        machineid, err = machine_id.communicate()
        print "\n'" + constants.machine_id_file + "' is present as: %s" %machineid
    else:
        pytest.fail("'" + constants.machine_id_file + "' is not present")
        print err

def test_no_upload_option():
    no_upload = subprocess.Popen([constants.app_name + " --no-upload"], stdout=subprocess.PIPE, shell=True)
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
    print "Deleted tar file %s" %tar_file

def test_no_tar_file_option():
    no_tar_file = subprocess.Popen([constants.app_name + " --no-tar-file"], stdout=subprocess.PIPE, shell=True)
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
    version_regex = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
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

def test_custom_config():
    custom_config = subprocess.Popen([constants.app_name + " --conf=./test/data/test-custom.conf"], stdout=subprocess.PIPE,shell=True)
    custom_config_output, err = custom_config.communicate()
    print custom_config_output
    if re.search("not yet been registered", custom_config_output)  is not None:
        print "Successfully used the passed configuration file"
    else:
        print err
        pytest.fail("Did not use passed configuration file")
