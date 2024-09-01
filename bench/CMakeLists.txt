aux_source_directory(. BPFNIC_BENCH_SRCS)

find_package(PkgConfig REQUIRED)
# due to libbpf
pkg_search_module(ZLIB REQUIRED zlib)
pkg_search_module(LIBELF REQUIRED libelf)

find_package(benchmark REQUIRED)

add_executable(bpfnic-bench ${BPFNIC_BENCH_SRCS})
add_dependencies(bpfnic-bench libbpf)
add_dependencies(bpfnic-bench bpf)

target_link_libraries(bpfnic-bench benchmark::benchmark
	bpfnic-obj
	${CMAKE_BINARY_DIR}/libbpf/libbpf.a
	z
	elf
)

if (BPFNIC_OPT_BUILD_STATIC)
	target_link_libraries(bpfnic-bench "-static")
endif (BPFNIC_OPT_BUILD_STATIC)

target_include_directories(bpfnic-bench PRIVATE ${CMAKE_BINARY_DIR}/libbpf/usr/include)
target_include_directories(bpfnic-bench PRIVATE ../include)
target_include_directories(bpfnic-bench PRIVATE ../bpf)
target_include_directories(bpfnic-bench PRIVATE ../src)
target_include_directories(bpfnic-bench PRIVATE .)
