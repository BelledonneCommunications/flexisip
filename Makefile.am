
ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST=flexisip.spec.in flexisip.spec

SUBDIRS=src scripts doc


# `make rpm'

.phony: rpm deb

rpm:
	$(MAKE) dist
# <https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=206841>
	TAR_OPTIONS=--wildcards rpmbuild -ta --clean --rmsource --rmspec $(PACKAGE)-$(VERSION).tar.gz

deb:
	scripts/update_debian_changelog.sh $(PACKAGE) $(VERSION)
	$(MAKE) dist
	mv $(distdir).tar.gz ../$(PACKAGE)_$(VERSION).orig.tar.gz
	DEB_BUILD_OPTIONS="nostrip debug" dpkg-buildpackage -us -uc
