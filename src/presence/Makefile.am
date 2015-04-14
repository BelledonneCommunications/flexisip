if BUILD_PRESENCE
lib_LTLIBRARIES = libflexisip-presence.la
libflexisip_presence_la_SOURCES = 	presence-server.cc presence-server.h \
					presentity-presenceinformation.cc presentity-presenceinformation.hh \
					signaling-exception.cc signaling-exception.hh\
					subscription.cc subscription.hh etag-manager.hh presentity-manager.hh
							
libflexisip_presence_la_LIBADD= libxml_binding_generated.la $(ORTP_LIBS) $(BELLESIP_LIBS) $(XERCESC_LIBS)
							 
AM_CPPFLAGS= -I $(abs_srcdir)/../ -I$(builddir)/xml $(SOFIA_CFLAGS) -DBELLE_SIP_USE_STL=1 $(BELLESIP_CFLAGS) $(ORTP_CFLAGS) $(XSDCXX_CPPFLAGS) $(XERCESC_CFLAGS)  
AM_LDFLAGS= 

endif
