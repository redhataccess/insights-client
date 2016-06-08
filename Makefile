TOPDIR=$(shell bash -c "pwd -P")
RPMTOP=$(TOPDIR)/dist
PKGNAME=insights-client
SRPM=$(RPMTOP)/SRPMS/$(PKGNAME)-*.src.rpm
TARBALL=$(RPMTOP)/$(PKGNAME)-*.tar.gz
TAR_PORTABLE=$(TOPDIR)/$(PKGNAME)-*.tar.gz
RPM=$(RPMTOP)/RPMS/noarch/$(PKGNAME)*.rpm
CONSTANTS=$(TOPDIR)/$(PKGNAME)/constants.py
PY_SDIST=python setup.py sdist
CONF_ORIG=default_conf_dir = '\/etc\/' + app_name + '\/'
CONF_PORT=default_conf_dir = package_path + '\/etc\/'


all: rpm

.PHONY: tarball
tarball: $(TARBALL)
$(TARBALL): Makefile
	$(PY_SDIST)

.PHONY: tar_portable
tar_portable: $(TAR_PORTABLE)
$(TAR_PORTABLE): Makefile
	sed -i "s/$(CONF_ORIG)/$(CONF_PORT)/" $(CONSTANTS)
	$(PY_SDIST)
	sed -i "s/$(CONF_PORT)/$(CONF_ORIG)/" $(CONSTANTS)
	mv $(TARBALL) $(RPMTOP)/..

.PHONY: srpm rpm 
srpm: $(SRPM)
$(SRPM): $(TAR_PORTABLE) $(TARBALL) $(SPEC_FILE_IN)
	mkdir -p $(RPMTOP)/{RPMS,SPECS,SRPMS,SOURCES,BUILD,BUILDROOT}
	rpmbuild -ts --define="_topdir $(RPMTOP)" --define="_sourcedir dist" $(TARBALL)

.PHONY: rpm
rpm: $(RPM)
$(RPM): $(SRPM)
	rpmbuild --buildroot $(RPMTOP)/BUILDROOT --define="_topdir $(RPMTOP)" --rebuild $<

install: $(RPM)
	sudo yum install -y $(RPM)

clean:
	rm -rf dist
	rm -f MANIFEST
	rm -rf *.egg*
	rm -f $(TAR_PORTABLE)
	find . -type f -name '*.pyc' -delete
