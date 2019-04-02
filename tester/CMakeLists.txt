
set(SOURCE_FILES_CXX 	tester.cc tester.hh
			boolean-expressions.cc
)


add_executable(flexisip_tester ${SOURCE_FILES_CXX})
set_target_properties(flexisip_tester PROPERTIES LINKER_LANGUAGE CXX)

target_include_directories(flexisip_tester PUBLIC ${BCTOOLBOX_TESTER_INCLUDE_DIRS})

target_link_libraries(flexisip_tester ${FLEXISIP_LIBRARIES_FOR_TESTER} ${BCTOOLBOX_LIBRARIES})