%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}
%define _binaries_in_noarch_packages_terminate_build 0

Name:                   redhat-access-insights
Summary:                Uploads Insights information to Red Hat on a periodic basis
Version:                1.0.13
Release:                7%{?dist}
Source0:                https://github.com/redhataccess/insights-client/archive/redhat-access-insights-%{version}.tar.gz
Epoch:                  0
License:                GPLv2+
URL:                    http://access.redhat.com/insights
Group:                  Applications/System
Vendor:                 Red Hat, Inc.

Obsoletes: redhat-access-proactive

Requires: python
Requires: python-setuptools
Requires: python-requests >= 2.6
Requires: pyOpenSSL
Requires: libcgroup
Requires: tar
Requires: gpg
Requires: pciutils
%if 0%{?rhel} && 0%{?rhel} > 6
Requires: libcgroup-tools
%endif
BuildArch: noarch

BuildRequires: python2-devel
BuildRequires: python-setuptools

%description
Sends insightful information to Red Hat for automated analysis

%prep
%setup -q

%install
rm -rf ${RPM_BUILD_ROOT}
%{__python} setup.py install --root=${RPM_BUILD_ROOT} $PREFIX

%post
#Migrate existing machine-id
if  [ -f "/etc/redhat_access_proactive/machine-id" ]; then
mkdir -p /etc/redhat-access-insights/
mv /etc/redhat_access_proactive/machine-id /etc/redhat-access-insights/machine-id
fi

%postun
if [ "$1" -eq 0 ]; then
rm -f /etc/cron.daily/redhat-access-insights
rm -f /etc/cron.weekly/redhat-access-insights
rm -f /etc/redhat-access-insights/.cache*
rm -f /etc/redhat-access-insights/.registered
rm -f /etc/redhat-access-insights/.unregistered
fi

%clean
test "x$RPM_BUILD_ROOT" != "x" && rm -rf $RPM_BUILD_ROOT

%files
%defattr(755,root,root)
%{_bindir}/redhat-access-insights
/etc/redhat-access-insights/redhat-access-insights.cron

%defattr(0600, root, root)
%dir /etc/redhat-access-insights
%config(noreplace) /etc/redhat-access-insights/*.conf
/etc/redhat-access-insights/.fallback.json
/etc/redhat-access-insights/.fallback.json.asc
/etc/redhat-access-insights/redhattools.pub.gpg
/etc/redhat-access-insights/.exp.sed
/etc/redhat-access-insights/*.pem

%defattr(-,root,root)
%{python_sitelib}/redhat_access_insights*.egg-info
%{python_sitelib}/redhat_access_insights/*.py*
%{_sharedstatedir}/redhat_access_insights/redhat-access-insights-*.tar.gz

%doc
/usr/share/man/man8/*.8.gz
/usr/share/man/man5/*.5.gz

%changelog
* Wed Dec 6 2017 Jeremy Crafts <jcrafts@redhat.com> - 1.0.13-7
- Fix compatibility issue with newer versions of python-requests

* Tue Sep 12 2017 Richard Brantley <rbrantle@redhat.com> - 1.0.13-6
- Resolves: bz1490450
- Fixes proxy hostname validation issues

* Mon Jun 26 2017 Richard Brantley <rbrantle@redhat.com> - 1.0.13-5
- Fixes cert_verify and --test-connection

* Tue Jan 17 2017 Richard Brantley <rbrantle@redhat.com> - 1.0.13-4
- Updates some man page verbiage
- Displays error messages and status codes from API
- Fixes traceback on improper API response
- Include build number in version output for support

* Fri Jan 13 2017 Richard Brantley <rbrantle@redhat.com> - 1.0.13-3
- Adds Machine ID and Account Numbers to STDOUT and logs

* Wed Jan 4 2017 Richard Brantley <rbrantle@redhat.com> - 1.0.13-2
- Fixes NO_PROXY checks
- Fixes support tool
- Resolves: bz1368237

* Thu Dec 1 2016 Richard Brantley <rbrantle@redhat.com> - 1.0.13-1
- Fixes subscription manager host-name issues
- Resolves: bz1393901

* Fri Nov 4 2016 Richard Brantley <rbrantle@redhat.com> - 1.0.12-0
- Respects NO_PROXY, HTTPS_PROXY environment variables
- Fixes remove.conf configuration issues
- Fixes timezone and file encoding related issues
- Adds new support for wildcard directories and files
- Fixes issue where invalid proxy would hang registration check
- Fixes some test cases
- Adds support for integration with Coordinators
- Resolves: bz1368237, bz1358354, bz1357964, bz1356939

* Fri Aug 26 2016 Jeremy Crafts <jcrafts@redhat.com> - 1.0.11-4
- Resolves: bz1320581, bz1323150, bz1323187, bz1325111

* Thu Apr 07 2016 Jeremy Crafts <jcrafts@redhat.com> - 1.0.9-0
- Bugfixes for connection test and stdout options 

* Fri Mar 04 2016 Jeremy Crafts <jcrafts@redhat.com> - 1.0.8-0
- Fix scheduling-related issues
- Add status check for registration with API
- Fix connectivity bug
- Improved debug messaging
- Resolves: bz1257238, bz1267303, bz1268002, bz1276058, bz1295928, bz1295931, bz1295932, bz1295934, bz1295940, bz1310242, bz1310243

* Tue Aug 11 2015 Dan Varga <dvarga@redhat.com> - 1.0.6-0
- Fix unregister -> reregister flow
- Resolves: bz1252435

* Mon Jun 08 2015 Dan Varga <dvarga@redhat.com> - 1.0.4-0
- Improved logging of exceptions
- Redact passwords automatically

* Mon Jun 01 2015 Dan Varga <dvarga@redhat.com> - 1.0.3-0
- New default URLs
- New config file format
- Default to auto configuration

* Mon May 18 2015 Dan Varga <dvarga@redhat.com> - 1.0.2-0
- Update man pages

* Thu May 07 2015 Dan Varga <dvarga@redhat.com> - 1.0.1-0
- Add man pages
- New certificate chain for cert-api.access.redhat.com
- Better auto configuration for satellite installations

* Wed Apr 29 2015 Dan Varga <dvarga@redhat.com> - 1.0.0-2
- Drop min python-requests version to 2.4

* Mon Apr 27 2015 Dan Varga <dvarga@redhat.com> - 1.0.0-1
- Add LICENSE file
- Resolves: bz1215002

* Thu Apr 23 2015 Dan Varga <dvarga@redhat.com> - 1.0.0-0
- Initial build
- Resolves: bz1176237
