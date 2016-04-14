
FROM registry.access.redhat.com/rhel

# the following 'yum search' should not be needed, but the
#    'yum-config-manager --enable rhel-7-server-extras-rpms'
#    doesn't seem to take effect unless this search is here
RUN yum search docker

# needed for python-docker-py and atomic
RUN yum-config-manager --enable rhel-7-server-extras-rpms


RUN yum update -y

# if you put these all on one line, yum doesn't report failure to install an rpm that docker notices
RUN yum install -y atomic
RUN yum install -y python-docker-py
RUN yum install -y python-setuptools
RUN yum install -y python2-devel
RUN yum install -y python-requests
RUN yum install -y python-magic
RUN yum install -y tar

RUN yum clean -y all

COPY docs /src/insights-client/docs
COPY etc /src/insights-client/etc
COPY redhat_access_insights /src/insights-client/redhat_access_insights
COPY scripts /src/insights-client/scripts
COPY LICENSE MANIFEST.in setup.cfg setup.py /src/insights-client/

# install the client
#   but delete the config directory's content because we must mount that from the host
RUN cd /src/insights-client; python setup.py install; rm -rf /etc/redhat-access-insights/*

