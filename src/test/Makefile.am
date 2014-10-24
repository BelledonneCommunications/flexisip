AUTOMAKE_OPTIONS = subdir-objects
check_PROGRAMS=expr
expr_SOURCES=expr.cc ../expressionparser.cc ../expressionparser.hh ../sipattrextractor.hh
expr_CXXFLAGS=-DTEST_BOOL_EXPR -DNO_SOFIA $(MEDIASTREAMER_CFLAGS)
expr_LDADD=$(MEDIASTREAMER_LIBS) 

