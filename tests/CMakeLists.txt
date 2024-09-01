enable_testing()

aux_source_directory(. BPFNIC_TEST_SRCS)

find_package(PkgConfig REQUIRED)
# due to libbpf
pkg_search_module(ZLIB REQUIRED zlib)
pkg_search_module(LIBELF REQUIRED libelf)

find_package(GTest REQUIRED)

add_executable(bpfnic-test ${BPFNIC_TEST_SRCS})
add_test(bpfnic-test ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/bpfnic-test)
add_dependencies(bpfnic-test libbpf)
add_dependencies(bpfnic-test bpf)

target_link_libraries(bpfnic-test gtest
	bpfnic-obj
	${CMAKE_BINARY_DIR}/libbpf/libbpf.a
	z
	elf
)

if (BPFNIC_OPT_BUILD_STATIC)
	target_link_libraries(bpfnic-test "-static")
endif (BPFNIC_OPT_BUILD_STATIC)

target_include_directories(bpfnic-test PRIVATE ${CMAKE_BINARY_DIR}/libbpf/usr/include)
target_include_directories(bpfnic-test PRIVATE ../include)
target_include_directories(bpfnic-test PRIVATE ../bpf)
target_include_directories(bpfnic-test PRIVATE ../src)
target_include_directories(bpfnic-test PRIVATE .)
