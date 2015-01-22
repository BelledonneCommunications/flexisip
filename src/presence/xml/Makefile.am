noinst_LTLIBRARIES=libpresence_generated.la

libpresence_generated_la_CFLAGS= $(STRICT_OPTIONS) $(STRICT_OPTIONS_CC)


nodist_libpresence_generated_la_SOURCES= \
					 xml.hxx  xml.cxx \
					 pidf+xml.hxx  pidf+xml.cxx 
.xsd.hxx .xsd.cxx:
	$(XSDCXX) cxx-tree --generate-wildcard --generate-serialization --generate-ostream --generate-detach --std c++11 --type-naming java \
	--function-naming java  --location-regex-trace --location-regex "%http://.+/(.+)%\$$1%" --output-dir $(builddir)  $<


AM_CPPFLAGS=$(XSDCXX_CPPFLAGS)  $(XERCESC_CFLAGS)

EXTRA_DIST= xml.xsd pidf+xml.xsd

CLEANFILES=$(nodist_libpresence_generated_la_SOURCES)
