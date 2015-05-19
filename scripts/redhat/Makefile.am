#Copying and distribution of this file, with or without modification,
#are permitted in any medium without royalty provided the copyright
#notice and this notice are preserved.  This file is offered as-is,
#without any warranty

EXTRA_DIST=flexisip.in

if USE_RPM

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

CLEANFILES=flexisip