GITVERSION_FILE=flexisip_gitversion.h
GITVERSION_FILE_TMP=flexisip_gitversion.h.tmp
GITDESCRIBE=`git describe`
GITREVISION=`git rev-parse HEAD`
AUTOMAKE_OPTIONS = subdir-objects

ECHO=/bin/echo

CLEANFILES=$(GITVERSION_FILE)
BUILT_SOURCES=$(GITVERSION_FILE)

SUBDIRS=test

bin_PROGRAMS=flexisip
thesources= \
			agent.cc agent.hh \
			common.cc common.hh \
			sdp-modifier.hh  sdp-modifier.cc \
			callstore.hh  callstore.cc \
			forkcontext.hh forkcontext.cc \
			callcontext-mediarelay.hh  callcontext-mediarelay.cc \
			forkcallcontext.hh  forkcallcontext.cc \
			forkmessagecontext.hh  forkmessagecontext.cc \
			forkbasiccontext.cc forkbasiccontext.hh \
			registrardb-internal.cc registrardb-internal.hh registrardb.cc registrardb.hh \
			recordserializer-c.cc recordserializer.hh \
			recordserializer-json.cc cJSON.c cJSON.h \
			etchosts.cc etchosts.hh \
			lpconfig.cc lpconfig.h \
			configmanager.cc configmanager.hh\
			event.cc event.hh \
			transaction.cc transaction.hh \
			module.cc module.hh \
			entryfilter.cc entryfilter.hh \
			stun.cc stun.hh \
			mediarelay.cc mediarelay.hh \
			authdb.hh authdb.cc authdb-file.cc \
			module-sanitychecker.cc \
			module-garbage-in.cc \
			module-forward.cc \
			module-gatewayadapter.cc \
			module-contact-route-inserter.cc \
			module-nat-helper.cc \
			module-registrar.cc \
			module-router.cc lateforkapplier.hh \
			module-transcode.cc \
			module-mediarelay.cc \
			module-auth.cc \
			module-loadbalancer.cc \
			dos-protection.cc dos-protection.hh \
			expressionparser.cc expressionparser.hh \
			sipattrextractor.cc sipattrextractor.hh \
			h264iframefilter.cc h264iframefilter.hh \
			telephone-event-filter.cc telephone-event-filter.hh \
			log/logmanager.cc log/logmanager.hh \
			eventlogs/eventlogs.cc eventlogs/eventlogs.hh \
			contact-masquerader.cc contact-masquerader.hh \
			uac-register.cc uac-register.hh \
			$(GITVERSION_FILE) 


if BUILD_SNMP
thesources+=snmp-agent.cc snmp-agent.h
AM_CPPFLAGS=-Imib			
endif

flexisip_LDADD=$(SOFIA_LIBS) $(ORTP_LIBS) $(MEDIASTREAMER_LIBS) $(HIREDIS_LIBS) $(PROTOBUF_LIBS) $(NETSNMPAGENT_LIBS)

AM_CXXFLAGS=$(SOFIA_CFLAGS) $(ORTP_CFLAGS) $(MEDIASTREAMER_CFLAGS) $(HIREDIS_CFLAGS) $(PROTOBUF_CFLAGS)  \
			-DCONFIG_DIR=\"$(CONFIG_DIR)\" -DORTP_DEBUG_MODE $(WARNINGCXXFLAGS)
AM_CFLAGS=$(ORTP_CFLAGS) $(MEDIASTREAMER_CFLAGS) -DORTP_DEBUG_MODE

if USE_MONOTONIC_CLOCK
AM_CXXFLAGS+=-DUSE_MONOTONIC_CLOCK
endif

if WITHOUT_HIREDIS_CONNECT_CALLBACK
AM_CXXFLAGS +=-DWITHOUT_HIREDIS_CONNECT_CALLBACK
endif

if BUILD_ODBC
AM_CFLAGS+=-DENABLE_ODBC
AM_CXXFLAGS+=-DENABLE_ODBC
flexisip_LDADD+=$(ODBC_LIBS)
thesources+= authdb-odbc.cc
endif

if BUILD_DATEHANDLER
thesources+=module-datehandler.cc
endif

if BUILD_TRANSCODER
thesources+=	callcontext-transcoder.cc callcontext-transcoder.hh  
endif

if BUILD_BOOSTLOG
AM_CXXFLAGS+=-DENABLE_BOOSTLOG -DBOOST_LOG_USE_NATIVE_SYSLOG=1 $(BOOST_CPPFLAGS) $(BOOST_LOG_CPPFLAGS) $(BOOST_REGEX_CPPFLAGS) $(BOOST_THREAD_CPPFLAGS)

flexisip_LDADD+=$(BOOST_LDFLAGS) $(BOOST_SYSTEM_LIB) $(BOOST_LOG_LIB) $(BOOST_REGEX_LIB) $(BOOST_THREAD_LIB) libhack.a
noinst_LIBRARIES = libhack.a
libhack_a_SOURCES = log/workaround.cc log/logmanager.hh
libhack_a_CXXFLAGS = $(AM_CXXFLAGS) -Wno-uninitialized

AM_CXXFLAGS+= -DBOOST_LOG_DYN_LINK=1
endif

if BUILD_PUSHNOTIFICATION
thesources+=module-pushnotification.cc \
			pushnotification/pushnotification.cc pushnotification/pushnotification.hh \
			pushnotification/pushnotificationservice.cc pushnotification/pushnotificationservice.hh \
			pushnotification/pushnotificationclient.cc pushnotification/pushnotificationclient.hh 
AM_CXXFLAGS+=-DENABLE_PUSHNOTIFICATION $(BOOST_CPPFLAGS) $(OPENSSL_CPPFLAGS)
flexisip_LDADD+=$(BOOST_LDFLAGS) $(BOOST_SYSTEM_LIB) $(OPENSSL_LIBS) $(BOOST_ASIO_LIB)
endif

if BUILD_REDIS
thesources+=registrardb-redis-sync.cc registrardb-redis-async.cc registrardb-redis.hh \
        registrardb-redis-sofia-event.h
AM_CXXFLAGS+=-DENABLE_REDIS
endif

nodistsources=
pb_files=$(srcdir)/recordserializer-protobuf.proto
if BUILD_PROTOBUF
$(builddir)/pb_generated_src_stamp : $(pb_files)
	protoc --proto_path=$(builddir) --cpp_out=$(builddir) $(pb_files)
	touch $(builddir)/pb_generated_src_stamp

BUILT_SOURCES+=$(builddir)/pb_generated_src_stamp 

thesources+=recordserializer-protobuf.cc
nodistsources+=recordserializer-protobuf.pb.cc recordserializer-protobuf.pb.h
AM_CXXFLAGS+=-DENABLE_PROTOBUF
AM_CFLAGS+=-DENABLE_PROTOBUF
endif
    
if BUILD_REDIS
bin_PROGRAMS+=ctdumper serializer binder
ctdumper_SOURCES=tool/ctdumper.cc $(thesources)
ctdumper_LDADD=$(flexisip_LDADD)
nodist_ctdumper_SOURCES=$(nodistsources)
endif

serializer_SOURCES=test/serializer.cc test/test_utils.hh $(thesources)
serializer_LDADD=$(flexisip_LDADD)
nodist_serializer_SOURCES=$(nodistsources)

binder_SOURCES=test/binder.cc test/test_utils.hh $(thesources)
binder_LDADD=$(flexisip_LDADD)
nodist_binder_SOURCES=$(nodistsources)

if BUILD_PUSHNOTIFICATION
bin_PROGRAMS+=pusher
pusher_SOURCES=tool/pusher.cc $(thesources)
pusher_LDADD=$(flexisip_LDADD)
nodist_pusher_SOURCES=$(nodistsources)
endif

flexisip_SOURCES=main.cc $(thesources)
nodist_flexisip_SOURCES=$(nodistsources)
EXTRA_DIST=$(pb_files) $(GITVERSION_FILE) tool/ctdumper.cc


clean-local:
	rm -f $(builddir)/recordserializer-protobuf.pb* $(builddir)/pb_generated_src_stamp


make_gitversion_h:
	if test "$(GITDESCRIBE)" != "" ; then \
		$(ECHO) -n "#define FLEXISIP_GIT_VERSION \"$(GITDESCRIBE)\"" > $(GITVERSION_FILE_TMP) ; \
	elif test "$(GITREVISION)" != "" ; then \
		$(ECHO) -n "#define FLEXISIP_GIT_VERSION \"$(LINPHONE_VERSION)_$(GITREVISION)\"" > $(GITVERSION_FILE_TMP) ; \
	else \
		$(ECHO) -n "" > $(GITVERSION_FILE_TMP) ; \
	fi
	if test ! -f $(srcdir)/$(GITVERSION_FILE) ; then \
		cp -f $(GITVERSION_FILE_TMP) $(srcdir)/$(GITVERSION_FILE) ; \
	fi
	if test "`cat $(GITVERSION_FILE_TMP)`" != "`cat $(srcdir)/$(GITVERSION_FILE)`" ; then \
		cp -f $(GITVERSION_FILE_TMP) $(srcdir)/$(GITVERSION_FILE) ; \
	fi
	rm -f $(GITVERSION_FILE_TMP) ;

$(GITVERSION_FILE): make_gitversion_h
