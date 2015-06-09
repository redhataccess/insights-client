# !/usr/bin/python

from setuptools import setup, find_packages
from distutils.sysconfig import get_python_lib


def get_version():
    f = open('redhat_access_insights/constants.py')
    for line in f:
        if 'version' in line:
            return eval(line.split('=')[-1])

VERSION = get_version()
SHORT_DESC = "Red Hat Access Insights"
LONG_DESC = """
Uploads insightful information to Red Hat
"""

if __name__ == "__main__":
    logpath = "/var/log/redhat-access-insights"

    # where stuff lands
    confpath = "/etc/redhat-access-insights"

    man5path = "/usr/share/man/man5/"
    man8path = "/usr/share/man/man8/"

    setup(
        name="redhat-access-insights",
        version=VERSION,
        author="Dan Varga",
        author_email="dvarga@redhat.com",
        license="GPL",
        packages=find_packages(),
        install_requires=['requests'],
        include_package_data=True,
        scripts=[
            "scripts/redhat-access-insights"
        ],
        entry_points={'console_scripts': ['redhat-access-insights = redhat_access_insights:_main']},
        data_files=[
            # config files
            (confpath, ['etc/redhat-access-insights.conf',
                        'etc/.fallback.json',
                        'etc/.fallback.json.asc',
                        'etc/redhattools.pub.gpg',
                        'etc/api.access.redhat.com.pem',
                        'etc/cert-api.access.redhat.com.pem',
                        'etc/.exp.sed',
                        'etc/redhat-access-insights.cron']),

            # man pages
            (man5path, ['docs/redhat-access-insights.conf.5']),
            (man8path, ['docs/redhat-access-insights.8']),

            (logpath, [])
        ],
        description=SHORT_DESC,
        long_description=LONG_DESC
    )
