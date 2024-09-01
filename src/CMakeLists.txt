aux_source_directory(. BPFNIC_SRCS)
list(REMOVE_ITEM BPFNIC_SRCS ./Main.cpp)

find_package(PkgConfig REQUIRED)
# due to libbpf
pkg_search_module(ZLIB REQUIRED zlib)
pkg_search_module(LIBELF REQUIRED libelf)

add_library(bpfnic-obj OBJECT ${BPFNIC_SRCS})
add_executable(bpfnic Main.cpp)
add_dependencies(bpfnic-obj libbpf)
add_dependencies(bpfnic libbpf)
add_dependencies(bpfnic bpf)

target_link_libraries(bpfnic
	bpfnic-obj
	${CMAKE_BINARY_DIR}/libbpf/libbpf.a
	z
	elf
)

if (BPFNIC_OPT_BUILD_STATIC)
	target_link_libraries(bpfnic "-static")
endif (BPFNIC_OPT_BUILD_STATIC)

target_include_directories(bpfnic-obj PRIVATE ${CMAKE_BINARY_DIR}/libbpf/usr/include)
target_include_directories(bpfnic-obj PRIVATE ../include)
target_include_directories(bpfnic-obj PRIVATE ../bpf)
target_include_directories(bpfnic-obj PRIVATE .)
target_include_directories(bpfnic PRIVATE ${CMAKE_BINARY_DIR}/libbpf/usr/include)
target_include_directories(bpfnic PRIVATE ../include)
target_include_directories(bpfnic PRIVATE ../bpf)
target_include_directories(bpfnic PRIVATE .)

