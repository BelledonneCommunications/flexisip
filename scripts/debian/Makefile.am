EXTRA_DIST=flexisip.in update_debian_changelog.sh

if USE_DEB

edit = sed -e 's|@bindir[@]|$(bindir)|g'

flexisip: Makefile
	rm -f $@ $@.tmp
	srcdir=''; \
	test -f ./$@.in || srcdir=$(srcdir)/; \
		$(edit) $${srcdir}$@.in >$@.tmp
	chmod +x $@.tmp
	chmod a-w $@.tmp
	mv $@.tmp $@

flexisip: $(srcdir)/flexisip.in

initdir=$(sysconfdir)/init.d

init_SCRIPTS=flexisip

endif
