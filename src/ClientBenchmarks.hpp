#ifndef _CLIENT_BENCHMARKS_H
#define _CLIENT_BENCHMARKS_H

#include <string>

void debugBenchmark(std::string serverIP, int benchmarkPort, int numClients);
void bimodalIncreasingBenchmark(std::string serverIP, int benchmarkPort, int numClients);
void unimodalIncreasingBenchmark(std::string serverIP, int benchmarkPort, int numClients);

#endif
