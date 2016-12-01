#Copying and distribution of this file, with or without modification,
#are permitted in any medium without royalty provided the copyright
#notice and this notice are preserved.  This file is offered as-is,
#without any warranty
EXTRA_DIST=flexisip.in flexisip-presence.in update_debian_changelog.sh

if USE_DEB
if !CROSS_COMPILING

edit = sed -e 's|@bindir[@]|$(bindir)|g'

flexisip: Makefile $(srcdir)/flexisip.in
	rm -f $@ $@.tmp
	srcdir=''; \
	test -f ./$@.in || srcdir=$(srcdir)/; \
		$(edit) $${srcdir}$@.in >$@.tmp
	chmod +x $@.tmp
	chmod a-w $@.tmp
	mv $@.tmp $@


flexisip-presence: Makefile $(srcdir)/flexisip-presence.in
	rm -f $@ $@.tmp
	srcdir=''; \
	test -f ./$@.in || srcdir=$(srcdir)/; \
		$(edit) $${srcdir}$@.in >$@.tmp
	chmod +x $@.tmp
	chmod a-w $@.tmp
	mv $@.tmp $@

initdir=$(sysconfdir)/init.d

init_SCRIPTS=flexisip flexisip-presence

endif
endif

CLEANFILES=flexisip flexisip-presence
