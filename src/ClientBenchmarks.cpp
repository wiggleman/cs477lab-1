/**
 * Defines CS477 lab-1 benchmark suites
 */

#include <Benchmark.hpp>
#include <string>
#include <vector>

#define DFL_WINDOW_DURATION 5
#define DFL_NUM_CLIENTS 5  // note that 2 threads will be spawned per client
#define DFL_THROUGHPUT 1'000

/**
 * Runs a short benchmark at the default throughput. Useful for debugging that
 * the server is correctly returning packets at a low throughput.
 */
void debugBenchmark(std::string serverIP, int benchmarkPort, int numClients) {
  auto benchRet = Benchmark::create(serverIP, benchmarkPort, numClients, DFL_WINDOW_DURATION, DFL_THROUGHPUT);
  if (benchRet.second != Err::NoError) {
    std::cerr << "benchmark creation failure" << std::endl;
    exit(1);
  }

  std::unique_ptr<Benchmark> benchmark = std::move(benchRet.first);
  std::cout << "client benchmark constructed" << std::endl;
  benchmark->run();
}

/**
 * runs a bimodal benchmark at increasing throughputs for 30 seconds.
 * Throughput grows exponentially at a rate of 5 seconds, starting at 10k Rps
 */
void bimodalIncreasingBenchmark(std::string serverIP, int benchmarkPort, int numClients) {
  // one-minute worth of default-duration windows
  std::vector<int> durations(6, DFL_WINDOW_DURATION);
  std::vector<int> throughputs;

  int throughput = 10'000;
  for (unsigned i = 0; i < durations.size(); i++) {
    throughputs.push_back(throughput);
    throughput *= 2;
  }

  auto benchRet = Benchmark::create_bimodal(serverIP, benchmarkPort, numClients, durations, throughputs);
  if (benchRet.second != Err::NoError) {
    std::cerr << "benchmark creation failure" << std::endl;
    exit(1);
  }

  std::unique_ptr<Benchmark> benchmark = std::move(benchRet.first);
  std::cout << "client benchmark constructed" << std::endl;
  benchmark->run();
}

/**
 * runs a unimodal benchmark at increasing throughputs for 30 seconds.
 * Throughput grows exponentially at a rate of 5 seconds, starting at 10k Rps
 */
void unimodalIncreasingBenchmark(std::string serverIP, int benchmarkPort, int numClients) {
  // one-minute worth of default-duration windows
  std::vector<int> durations(6, DFL_WINDOW_DURATION);
  std::vector<int> throughputs;

  int throughput = 10'000;
  for (unsigned i = 0; i < durations.size(); i++) {
    throughputs.push_back(throughput);
    throughput *= 2;
  }

  auto benchRet = Benchmark::create(serverIP, benchmarkPort, numClients, durations, throughputs);
  if (benchRet.second != Err::NoError) {
    std::cerr << "benchmark creation failure" << std::endl;
    exit(1);
  }

  std::unique_ptr<Benchmark> benchmark = std::move(benchRet.first);
  std::cout << "client benchmark constructed" << std::endl;
  benchmark->run();
}
