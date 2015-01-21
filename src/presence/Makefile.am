AUTOMAKE_OPTIONS = subdir-objects
if BUILD_PRESENCE
SUBDIRS= xml
lib_LTLIBRARIES = libflexisip-presence.la
libflexisip_presence_la_SOURCES = 	presence-server.cc \
					presentity-presenceinformation.cc \
					signaling-exception.cc \
					subscription.cc
							
libflexisip_presence_la_LIBADD= xml/libpresence_generated.la $(ORTP_LIBS) $(BELLESIP_LIBS) $(XERCESC_LIBS)
							 
AM_CPPFLAGS= -I $(abs_srcdir)/../ -I$(builddir)/xml $(SOFIA_CFLAGS) -DBELLE_SIP_USE_STL=1 $(BELLESIP_CFLAGS) $(ORTP_CFLAGS) $(XSDCXX_CPPFLAGS) $(XERCESC_CFLAGS)  
AM_LDFLAGS= 

endif
