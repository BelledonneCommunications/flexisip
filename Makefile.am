EXTRA_DIST=flexisip.spec.in flexisip.spec

SUBDIRS=src scripts doc


# `make rpm'

.phony: rpm

rpm:
	$(MAKE) dist
# <https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=206841>
	TAR_OPTIONS=--wildcards rpmbuild -ta --clean --rmsource --rmspec $(PACKAGE)-$(VERSION).tar.gz
