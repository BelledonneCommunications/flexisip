if BUILD_PRESENCE
lib_LTLIBRARIES = libflexisip-presence.la
libflexisip_presence_la_SOURCES = 	file-resource-list-manager.cc \
									module-presence.cc \
									resource-lists-pimpl.cxx \
									resource-lists-pskel.cxx \
									resource-lists.cxx \
									xml-pimpl.cxx \
									xml-pskel.cxx \
									xml.cxx
							
libflexisip_presence_la_LIBADD= $(XSDE_LIBS)
							 
AM_CPPFLAGS= -I ../ $(XSDE_CPPFLAGS)  $(SOFIA_CFLAGS)



endif