#!/usr/bin/python

# The following is so that insights-client continues to work normally in places where
# Docker is not installed.
#
# Note that this is actually testing if the python docker client is importable (is installed),
# and if the docker server on this machine is accessable, which isn't exactly the
# same thing as 'there is no docker on this machine'.

import logging

from redhat_access_insights.constants import InsightsConstants as constants

APP_NAME = constants.app_name
logger = logging.getLogger(APP_NAME)


# Check to see if we have access to docker through the "docker" python module
HaveDocker = False
HaveDockerException = None
try:
    import docker
    docker.Client(base_url='unix://var/run/docker.sock').images()
    HaveDocker = True

except Exception as e:
    HaveDockerException = e

if HaveDocker:
    import os
    import tempfile
    import shutil
    import shlex
    import subprocess

    from redhat_access_insights import InsightsClient

    def run_command_very_quietly(cmdline):
        # this takes a string (not an array)
        # need to redirect stdout and stderr to /dev/null
        cmd = shlex.split(cmdline)
        proc = subprocess.Popen(cmd)
        returncode = proc.wait()
        return returncode

    def runcommand(cmd):
        # this takes an array (not a string)
        logger.debug("Running Command: %s" % cmd)
        proc = subprocess.Popen(cmd)
        returncode = proc.wait()
        return returncode

    def get_image_name():
        if InsightsClient.options.docker_image_name:
            logger.debug("found docker_image_name in options: %s" % InsightsClient.options.docker_image_name)
            return InsightsClient.options.docker_image_name

        elif InsightsClient.config.get(APP_NAME, 'docker_image_name'):
            logger.debug("found docker_image_name in config: %s" % InsightsClient.config.get(APP_NAME, 'docker_image_name'))
            return InsightsClient.config.get(APP_NAME, 'docker_image_name')

        else:
            logger.debug("found docker_image_name in constants: %s" % constants.docker_image_name)
            return constants.docker_image_name

    def pull_image(image):
        return runcommand(shlex.split("docker pull") + [ image ])

    def insights_client_container_is_available():
        image_name = get_image_name()
        if image_name:
            client = docker.Client(base_url='unix://var/run/docker.sock')

            pull_image(image_name)

            images = client.images(image_name)
            if len(images) == 0:
                logger.debug("insights-client docker image not available: %s" % image_name)
                return False
            else:
                return True
        else:
            return False

    def run_in_container(options):
        # This script runs the insights-client in a docker container.
        #
        # This is using the docker client command, it should be changed to use the python docker
        # client.
        #
        # It takes exactly the same arguments and options as insights-client, and just passes them
        # on to the client running in the container.  But, this script currently only gives access
        # to a few necessary parts of the host file system, so the container can not gather data
        # from the host.  So the arguments should specify an option that does data gathering
        # from a container or image, because gathering from the host won't work.
        #
        # The insights-client configuration from the host is used by the container.
        #

        # the -v's in the following mount the host's directories into the containers directories
        #    /var/run/docker.sock ---- so we can use docker
        #    /var/lib/docker      ---- so we can mount docker images and containers
        #    /dev/                ----   also so we can mount docker images and containers
        #    /etc/redhat-access-insights --- so we can use the host's configuration and machine-id
        #    /etc/pki --- so we can use the host's Sat6 certs (if any)
        if options.from_file:
            logger.error('--from-file is incompatible with transfering to a container.')
            return 1

        docker_args = shlex.split("docker run --privileged=true -i -a stdin -a stdout -a stderr --rm -v /var/run/docker.sock:/var/run/docker.sock -v /var/lib/docker/:/var/lib/docker/ -v /dev/:/dev/ -v /etc/redhat-access-insights/:/etc/redhat-access-insights -v /etc/pki/:/etc/pki/ " + get_image_name() + " redhat-access-insights")

        return runcommand(docker_args + [ "--run-here" ] + InsightsClient.argv[1:])

    def get_targets():
        client = docker.Client(base_url='unix://var/run/docker.sock')
        targets = []
        if client:
            for d in client.images(quiet=True):
                targets.append({'type': 'docker_image', 'name': d})
            for d in client.containers(all=True, trunc=False):
                targets.append({'type': 'docker_container', 'name': d['Id']})
        return targets


    # Check to see if we have access to Atomic through the 'atomic' command
    HaveAtomic = False
    HaveAtomicException = None
    try:
        if run_command_very_quietly("atomic --version") == 0:
            # a returncode of 0 means cmd ran correctly
            HaveAtomic = True
        else:
            # anything else indicates problem
            HaveAtomic = False
    except Exception as e:
        # this happens when atomic isn't installed or is otherwise unrunable
        HaveAtomic = False
        HaveAtomicException = e

    if HaveAtomic:
        class AtomicTemporaryMountPoint:
            # this is used for both images and containers
            def __init__(self, image_id, mount_point):
                self.image_id = image_id
                self.mount_point = mount_point

            def get_fs(self):
                return self.mount_point

            def close(self):
                try:
                    logger.debug("Closing Id %s On %s" % (self.image_id, self.mount_point))
                    runcommand(shlex.split("atomic unmount") + [self.mount_point])
                except Exception as e:
                    logger.debug("exception while unmounting image or container: %s" % e)
                shutil.rmtree(self.mount_point, ignore_errors=True)

        def open_image(image_id):
            mount_point = tempfile.mkdtemp()
            logger.debug("Opening Image Id %s On %s using atomic" % (image_id, mount_point))
            if runcommand(shlex.split("atomic mount") + [image_id, mount_point]) == 0:
                return AtomicTemporaryMountPoint(image_id, mount_point)
            else:
                logger.error('Could not mount Image Id %s On %s' % (image_id, mount_point))
                shutil.rmtree(self.mount_point, ignore_errors=True)
                return None

        def open_container(container_id):
            mount_point = tempfile.mkdtemp()
            logger.debug("Opening Container Id %s On %s using atomic" % (container_id, mount_point))
            if runcommand(shlex.split("atomic mount") + [container_id, mount_point]) == 0:
                return AtomicTemporaryMountPoint(container_id, mount_point)
            else:
                logger.error('Could not mount Container Id %s On %s' % (container_id, mount_point))
                shutil.rmtree(self.mount_point, ignore_errors=True)
                return None

    else:
        from mount import DockerMount, Mount, MountError

        class DockerTemporaryMountPoint:
            # this is used for both images and containers
            def __init__(self, client, image_id, mount_point, cid):
                self.client = client
                self.image_id = image_id
                self.mount_point = mount_point
                self.cid = cid

            def get_fs(self):
                return self.mount_point

            def close(self):
                try:
                    logger.debug("Closing Id %s On %s" % (self.image_id, self.mount_point))
                    unmount_obj(self.client, self.mount_point, self.cid)
                except Exception as e:
                    logger.debug("exception while unmounting image or container: %s" % e)
                shutil.rmtree(self.mount_point, ignore_errors=True)

        def open_image(image_id):
            global HaveAtomicException
            if HaveAtomicException:
                logger.debug("using docker client to open images and containers")
                logger.debug("atomic is either not installed or not accessable %s" % HaveAtomicException);
                HaveAtomicException = None
            client = docker.Client(base_url='unix://var/run/docker.sock')
            if client:
                mount_point = tempfile.mkdtemp()
                logger.debug("Opening Image Id %s On %s using docker client" % (image_id, mount_point))
                cid = mount_obj(client, mount_point, image_id)
                if cid:
                    return DockerTemporaryMountPoint(client, image_id, mount_point, cid)
                else:
                    logger.error('Could not mount Image Id %s On %s' % (image_id, mount_point))
                    shutil.rmtree(self.mount_point, ignore_errors=True)
                    return None

            else:
                logger.error('Could not connect to docker to examine image %s' % image_id)
                return None

        def open_container(container_id):
            global HaveAtomicException
            if HaveAtomicException:
                logger.debug("using docker client to open images and containers")
                logger.debug("atomic is either not installed or not accessable %s" % HaveAtomicException);
                HaveAtomicException = None
            client = docker.Client(base_url='unix://var/run/docker.sock')
            if client:
                matching_containers = []
                for each in client.containers(all=True, trunc=False):
                    if container_id == each['Id']:
                        matching_containers = [ each ]
                        break
                if len(matching_containers) == 1:
                    mount_point = tempfile.mkdtemp()
                    logger.debug("Opening Container Id %s On %s using docker client" % (container_id, mount_point))
                    cid = mount_obj(client, mount_point, container_id)
                    if cid:
                        return DockerTemporaryMountPoint(client, container_id, mount_point, cid)
                    else:
                        logger.error('Could not mount Container Id %s On %s' % (container_id, mount_point))
                        shutil.rmtree(self.mount_point, ignore_errors=True)
                        return None

                else:
                    if len(matching_containers) > 1:
                        logger.error('%s containers match name %s' % (len(matching_containers), container_id))
                        for each in matching_containers:
                            logger.error('   %s %s' % (get_label(each), each['Id']))
                    else:
                        logger.error('no containers match name %s' % container_id)
                    return None
            else:
                logger.error('Could not connect to docker to examine container %s' % container_id)
                return None

        def mount_obj(client, path, obj):
            """ mounts the obj to the given path """

            # docker mount creates a temp image
            # we have to use this temp image id to remove the device
            path, new_cid = DockerMount(path).mount(obj)
            if client.info()['Driver'] == 'devicemapper':
                DockerMount.mount_path(os.path.join(path, "rootfs"), path, bind=True)

            return new_cid

        def unmount_obj(client, path, cid):
            """ unmount the given path """

            # If using device mapper, unmount the bind-mount over the directory
            if client.info()['Driver'] == 'devicemapper':
                Mount.unmount_path(path)

            DockerMount(path).unmount(cid)

else:
    # If we can't import docker then we stub out all the main functions to report errors

    def insights_client_container_is_available():
        # Don't print error here, this is the way to tell if running in a container is possible
        # but do print debug info
        logger.debug('not transfering to insights-client image')
        logger.debug('Docker is either not installed or not accessable: %s' % \
                     (HaveDockerException if HaveDockerException else ''))
        return False

    def run_in_container(options):
        logger.error('Could not connect to docker to examine image %s' % options.analyse_docker_image)
        logger.error('Docker is either not installed or not accessable: %s' % \
                     (HaveDockerException if HaveDockerException else ''))
        return 1

    def get_targets():
        logger.debug('Could not connect to docker to collect from images and containers')
        logger.debug('Docker is either not installed or not accessable: %s' % \
                     (HaveDockerException if HaveDockerException else ''))
        return []

    def open_image(image_id):
        logger.error('Could not connect to docker to examine image %s' % image_id)
        logger.error('Docker is either not installed or not accessable: %s' % \
                     (HaveDockerException if HaveDockerException else ''))
        return None

    def open_container(container_id):
        logger.error('Could not connect to docker to examine container %s' % container_id)
        logger.error('Docker is either not installed or not accessable: %s' % \
                     (HaveDockerException if HaveDockerException else ''))
        return None

