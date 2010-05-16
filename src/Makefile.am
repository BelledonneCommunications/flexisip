bin_PROGRAMS=bcproxy

bcproxy_SOURCES=main.cc \
			agent.cc agent.hh \
			common.cc common.hh \
			transcodeagent.cc transcodeagent.hh

AM_CXXFLAGS=$(SOFIA_CFLAGS) $(MEDIASTREAMER_CFLAGS)

AM_LDFLAGS=$(SOFIA_LIBS) $(MEDIASTREAMER_LIBS)
