SUBDIRS=debian redhat


configdir=$(sysconfdir)/flexisip

config_DATA=flexisip.conf.sample

all-local:	flexisip.conf.sample

flexisip.conf.sample:	$(top_builddir)/src/flexisip
	$(top_builddir)/src/flexisip --dump-default-config > $@

discovery:
	$(CXX) $(CXXFLAGS) $(SOFIA_CFLAGS) $(MEDIASTREAMER_CFLAGS) -E -P -v -dD specs.cpp

CLEANFILES=flexisip.conf.sample
