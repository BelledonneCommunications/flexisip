bin_PROGRAMS=flexisip
flexisip_SOURCES=main.cc \
			agent.cc agent.hh \
			common.cc common.hh \
			sdp-modifier.hh  sdp-modifier.cc \
			callstore.hh  callstore.cc \
			forkcontext.hh forkcontext.cc \
			forkcallcontext.hh  forkcallcontext.cc \
			forkmessagecontext.hh  forkmessagecontext.cc \
			callcontext.cc callcontext.hh \
			registrardb-internal.cc registrardb-internal.hh registrardb.cc registrardb.hh \
			etchosts.cc etchosts.hh \
			lpconfig.c lpconfig.h \
			configmanager.cc configmanager.hh\
			event.cc event.hh \
			transaction.cc transaction.hh \
			module.cc module.hh \
			entryfilter.cc entryfilter.hh \
			stun.cc stun.hh \
			mediarelay.cc mediarelay.hh \
			authdb.hh authdb.cc authdb-odbc.cc authdb-file.cc \
			module-forward.cc \
			module-transcode.cc \
			module-gatewayadapter.cc \
			module-contact-route-inserter.cc \
			module-nat-helper.cc \
			module-registrar.cc \
			module-mediarelay.cc \
			module-auth.cc \
			module-loadbalancer.cc \
			dos-protection.cc dos-protection.hh


if BUILD_SNMP
flexisip_SOURCES+=snmp-agent.cc snmp-agent.h
INCLUDES=-Imib			
endif

flexisip_LDADD=$(SOFIA_LIBS) $(MEDIASTREAMER_LIBS) $(ODBC_LIBS) $(HIREDIS_LIBS) $(PROTOBUF_LIBS) $(NETSNMPAGENT_LIBS)

AM_CXXFLAGS=$(SOFIA_CFLAGS) $(MEDIASTREAMER_CFLAGS) $(HIREDIS_CFLAGS) $(PROTOBUF_CFLAGS)  \
			-DCONFIG_DIR=\"$(CONFIG_DIR)\"
AM_CFLAGS=$(MEDIASTREAMER_CFLAGS) 


if BUILD_TRANSCODER
AM_CFLAGS+="-DENABLE_TRANSCODER"
AM_CXXFLAGS+="-DENABLE_TRANSCODER"
endif

if BUILD_PUSHNOTIFICATION
flexisip_SOURCES+=module-pushnotification.cc \
			apn/pushnotification.cc apn/pushnotification.h \
			apn/pushnotificationservice.cc apn/pushnotificationservice.h \
			apn/pushnotificationclient.cc apn/pushnotificationclient.h 
AM_CXXFLAGS+=-DENABLE_PUSHNOTIFICATION $(BOOST_CPPFLAGS)
flexisip_LDADD+=$(BOOST_LDFLAGS) $(BOOST_SYSTEM_LIB)
endif

if BUILD_REDIS
flexisip_SOURCES+=registrardb-redis-sync.cc registrardb-redis-async.cc registrardb-redis.hh \
        recordserializer-c.cc recordserializer.hh registrardb-redis-sofia-event.h \
        recordserializer-json.cc cJSON.c cJSON.h
AM_CXXFLAGS+=-DENABLE_REDIS
endif

pb_files=$(srcdir)/recordserializer-protobuf.proto
if BUILD_PROTOBUF
$(builddir)/pb_generated_src_stamp : $(pb_files)
	protoc --proto_path=$(builddir) --cpp_out=$(builddir) $(pb_files)
	touch $(builddir)/pb_generated_src_stamp

BUILT_SOURCES=$(builddir)/pb_generated_src_stamp

flexisip_SOURCES+=recordserializer-protobuf.cc
nodist_flexisip_SOURCES=recordserializer-protobuf.pb.cc recordserializer-protobuf.pb.h
AM_CXXFLAGS+="-DENABLE_PROTOBUF"
AM_CFLAGS+="-DENABLE_PROTOBUF"
endif
    
EXTRA_DIST=$(pb_files)


