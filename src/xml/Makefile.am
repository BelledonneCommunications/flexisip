noinst_LTLIBRARIES=libxml_binding_generated.la

libxml_binding_generated_la_CFLAGS= $(STRICT_OPTIONS) $(STRICT_OPTIONS_CC)

.xsd.hxx .xsd.cxx:
	$(XSDCXX) cxx-tree --generate-wildcard --generate-serialization --generate-ostream --generate-detach --std c++11 --type-naming java \
	--function-naming java  --location-regex-trace --location-regex "%http://.+/(.+)%\$$1%" --output-dir $(builddir)  $<

nodist_libxml_binding_generated_la_SOURCES = fthttp.hxx fthttp.cxx
EXTRA_DIST = fthttp.xsd
	
if BUILD_PRESENCE
nodist_libxml_binding_generated_la_SOURCES += xml.hxx  xml.cxx pidf+xml.hxx  pidf+xml.cxx 
EXTRA_DIST += xml.xsd pidf+xml.xsd

endif
AM_CPPFLAGS=$(XSDCXX_CPPFLAGS) $(XERCESC_CFLAGS)

CLEANFILES=$(nodist_libxml_binding_generated_la_SOURCES)
