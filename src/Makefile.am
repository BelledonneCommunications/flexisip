bin_PROGRAMS=flexisip

flexisip_SOURCES=main.cc \
			agent.cc agent.hh \
			common.cc common.hh \
			transcodeagent.cc transcodeagent.hh \
			offeranswer.c offeranswer.h \
			sdp-modifier.hh  sdp-modifier.cc \
			callstore.hh  callstore.cc

AM_CXXFLAGS=$(SOFIA_CFLAGS) $(MEDIASTREAMER_CFLAGS)

AM_LDFLAGS=$(SOFIA_LIBS) $(MEDIASTREAMER_LIBS)
