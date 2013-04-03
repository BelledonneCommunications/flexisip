
ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST=flexisip.spec.in flexisip.spec

SUBDIRS=src scripts doc debian


# `make rpm'

.phony: rpm deb

rpm:
	$(MAKE) dist
# <https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=206841>
	TAR_OPTIONS=--wildcards rpmbuild -ta --clean --rmsource --rmspec $(PACKAGE)-$(VERSION).tar.gz

SHORT_VERSION=$(shell echo $(VERSION)| sed 's/-.*//')

deb:
	scripts/update_debian_changelog.sh $(PACKAGE) $(VERSION)
	$(MAKE) dist
	rm -rf build-debian
	mkdir -p build-debian
	mv $(distdir).tar.gz build-debian/$(PACKAGE)_$(SHORT_VERSION).orig.tar.gz
	cd build-debian && tar -xvzf $(PACKAGE)_$(SHORT_VERSION).orig.tar.gz
	cd build-debian/$(PACKAGE)-$(VERSION) && DEB_BUILD_OPTIONS="nostrip debug" dpkg-buildpackage -us -uc -sa
	cp build-debian/*.{dsc,changes,deb,tar.gz} ..
