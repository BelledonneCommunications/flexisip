SUBDIRS=debian redhat


configdir=$(sysconfdir)/flexisip

config_DATA=flexisip.conf.sample

all-local:	flexisip.conf.sample

#if CROSS_COMPILING
flexisip.conf.sample:
	echo "#Empty config file due to cross compilation. Use flexisip --dump-default-config > flexisip.conf.sample on the target machine." > $@
#else
flexisip.conf.sample:	$(top_builddir)/src/flexisip
	$(top_builddir)/src/flexisip --dump-default-config > $@
#endif

#if BUILD_SNMP
	OTHER_FLAGS=-DENABLE_SNMP
#endif
#if BUILD_REDIS
	OTHER_FLAGS="$(OTHER_FLAGS) -DENABLE_REDIS"
#endif
#if BUILD_PROTOBUF
	OTHER_FLAGS="$(OTHER_FLAGS) -DENABLE_PROTOBUF"
#endif
	
discovery:
	$(CXX) $(CXXFLAGS) $(SOFIA_CFLAGS) $(MEDIASTREAMER_CFLAGS) $(OTHER_FLAGS) -E -P -v -dD specs.cpp

CLEANFILES=flexisip.conf.sample
