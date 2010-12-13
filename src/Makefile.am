bin_PROGRAMS=flexisip

flexisip_SOURCES=main.cc \
			agent.cc agent.hh \
			common.cc common.hh \
			sdp-modifier.hh  sdp-modifier.cc \
			callstore.hh  callstore.cc \
			callcontext.cc callcontext.hh \
			registrardb.cc registrardb.hh \
			etchosts.cc etchosts.hh \
			lpconfig.c lpconfig.h \
			configmanager.cc configmanager.hh\
			module.cc module.hh \
			entryfilter.cc entryfilter.hh \
			stun.cc stun.hh \
			mediarelay.cc mediarelay.hh \
			module-forward.cc \
			module-transcode.cc \
			module-contact-route-inserter.cc \
			module-nat-helper.cc \
			module-registrar.cc \
			module-mediarelay.cc

AM_CXXFLAGS=$(SOFIA_CFLAGS) $(MEDIASTREAMER_CFLAGS) \
			-DCONFIG_DIR=\"$(CONFIG_DIR)\"
AM_CFLAGS=$(MEDIASTREAMER_CFLAGS)

AM_LDFLAGS=$(SOFIA_LIBS) $(MEDIASTREAMER_LIBS)
