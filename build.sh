#!/bin/bash
rm -rf .build bpfnic bpfnic-test bpfnic-bench
pushd bpf
make clean
popd
mkdir .build
cd .build
cmake -G Ninja				\
 -DCMAKE_BUILD_TYPE=$BUILD_TYPE		\
 -DBPFNIC_OPT_BUILD_TESTS=ON		\
 -DBPFNIC_OPT_BUILD_BENCH=ON .. &&	\
 bear -- cmake --build . &&		\
cp src/bpfnic .. &&			\
cp tests/bpfnic-test .. &&		\
cp bench/bpfnic-bench .. &&		\
cp compile_commands.json ..
