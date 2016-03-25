#Copying and distribution of this file, with or without modification,
#are permitted in any medium without royalty provided the copyright
#notice and this notice are preserved.  This file is offered as-is,
#without any warranty

if BUILD_PRESENCE
lib_LTLIBRARIES = libflexisip-presence.la
libflexisip_presence_la_SOURCES = 	presence-server.cc presence-server.hh \
					presentity-presenceinformation.cc presentity-presenceinformation.hh \
					bellesip-signaling-exception.cc bellesip-signaling-exception.hh\
					subscription.cc subscription.hh etag-manager.hh presentity-manager.hh list-subscription.cc list-subscription.hh

libflexisip_presence_la_LIBADD= ../xml/libxml_binding_generated.la $(ORTP_LIBS) $(BELLESIP_LIBS) $(XERCESC_LIBS)

AM_CPPFLAGS= -I $(abs_srcdir)/../ -I$(builddir)/../xml $(SOFIA_CFLAGS) -DBELLE_SIP_USE_STL=1 $(BELLESIP_CFLAGS) $(ORTP_CFLAGS) $(XSDCXX_CPPFLAGS) $(XERCESC_CFLAGS)
AM_LDFLAGS=

endif
