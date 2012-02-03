bin_PROGRAMS=flexisip
flexisip_SOURCES=main.cc \
			agent.cc agent.hh \
			common.cc common.hh \
			sdp-modifier.hh  sdp-modifier.cc \
			callstore.hh  callstore.cc \
			callcontext.cc callcontext.hh \
			registrardb-internal.cc registrardb-internal.hh registrardb.cc registrardb.hh \
			etchosts.cc etchosts.hh \
			lpconfig.c lpconfig.h \
			configmanager.cc configmanager.hh\
			module.cc module.hh \
			entryfilter.cc entryfilter.hh \
			stun.cc stun.hh \
			mediarelay.cc mediarelay.hh \
			module-forward.cc \
			module-transcode.cc \
			module-gatewayadapter.cc \
			module-contact-route-inserter.cc \
			module-nat-helper.cc \
			module-registrar.cc \
			module-mediarelay.cc \
			module-auth.cc \
			auth-odbc.hh auth-odbc.cc \
			module-loadbalancer.cc


flexisip_LDADD=$(SOFIA_LIBS) $(MEDIASTREAMER_LIBS) $(ODBC_LIBS) $(HIREDIS_LIBS) $(PROTOBUF_LIBS)

AM_CXXFLAGS=$(SOFIA_CFLAGS) $(MEDIASTREAMER_CFLAGS) $(HIREDIS_CFLAGS) $(PROTOBUF_CFLAGS)  \
			-DCONFIG_DIR=\"$(CONFIG_DIR)\"
AM_CFLAGS=$(MEDIASTREAMER_CFLAGS)


if BUILD_REDIS
flexisip_SOURCES+=registrardb-redis-sync.cc registrardb-redis-async.cc registrardb-redis.hh \
        recordserializer-c.cc recordserializer.hh registrardb-redis-sofia-event.h \
        recordserializer-json.cc cJSON.c cJSON.h
AM_CXXFLAGS+="-DENABLE_REDIS"
endif

if BUILD_PROTOBUF
pb_files=$(srcdir)/recordserializer-protobuf.proto
$(builddir)/pb_generated_src_stamp : $(pb_files)
	protoc --proto_path=$(builddir) --cpp_out=$(builddir) $(pb_files)
	touch $(builddir)/pb_generated_src_stamp

BUILT_SOURCES=$(builddir)/pb_generated_src_stamp

flexisip_SOURCES+=recordserializer-protobuf.cc recordserializer-protobuf.pb.cc recordserializer-protobuf.pb.hh
AM_CXXFLAGS+="-DENABLE_PROTOBUF"
AM_CFLAGS+="-DENABLE_PROTOBUF"
endif
    


