AUTOMAKE_OPTIONS = subdir-objects
if BUILD_PRESENCE
lib_LTLIBRARIES = libflexisip-presence.la
libflexisip_presence_la_SOURCES = 	presence-server.cc \
									presence-configmanager.cc \
									presentity-presenceinformation.cc \
									file-resource-list-manager.cc \
									signaling-exception.cc \
									resource-list/resource-lists-pimpl.cxx \
									resource-list/resource-lists-pskel.cxx \
									resource-list/resource-lists.cxx \
									application_pidf+xml/pidf+xml-pimpl.cxx \
									application_pidf+xml/pidf+xml-pskel.cxx \
									application_pidf+xml/pidf+xml.cxx \
									xml/xml-pimpl.cxx \
									xml/xml-pskel.cxx \
									xml/xml.cxx
							
libflexisip_presence_la_LIBADD= $(XSDE_LIBS) $(BELLESIP_LIBS)
							 
AM_CPPFLAGS= -I $(abs_srcdir)/../ -I$(abs_srcdir)/xml -I$(abs_srcdir)/resource-list -I$(abs_srcdir)/application_pidf+xml $(XSDE_CPPFLAGS)  $(SOFIA_CFLAGS) $(BELLESIP_CFLAGS)
AM_LDFLAGS=

endif
