#ifndef _BENCHMARK_H
#define _BENCHMARK_H

/**
 * A benchmark wraps a vector of clients
 */
#include <memory>
#include <vector>

#include "Client.hpp"
#include "ThreadPool.cpp"

/**
 * A Benchmark manages the lifecycle of a vector of Clients, and manages their
 * execution.
 *
 * The benchmark is executed by window - traffic will be generated for a fixed
 * interval of time at a fixed throughput.
 *
 * @param clients a vector of Clients that will generate traffic asynchronously
 *		on dedicated threads.
 * @param numThreads the number of threads in the threadpool
 * @param windowDurations entry `i` represents how long the i'th window will
 *		execute for
 * @param windowThroughputs entry `i` represents the throughput of traffic in
 *		Rps that will be generated in the i'th window
 */
class Benchmark {
 public:
  Benchmark(std::vector<std::unique_ptr<Client>> clients, int numThreads, std::vector<int> windowDurations,
            std::vector<int> windowThroughputs)
      : clients(std::move(clients)),
        threadPool(numThreads),
        windowDurations(windowDurations),
        windowThroughputs(windowThroughputs) {}

  /// benchmark factory function
  static std::pair<std::unique_ptr<Benchmark>, Err::SocketError> create(std::string destIP, int port,
                                                                        unsigned numClients,
                                                                        std::vector<int> windowDurations,
                                                                        std::vector<int> windowThroughputs) {
    std::vector<std::unique_ptr<Client>> clients;

    for (unsigned i = 0; i < numClients; i++) {
      auto clientRet = Client::create(destIP, port);
      if (clientRet.second != Err::NoError) return {nullptr, clientRet.second};

      clients.push_back(std::move(clientRet.first));
    }

    return {std::make_unique<Benchmark>(std::move(clients), numClients * 2, windowDurations, windowThroughputs),
            Err::NoError};
  }

  /**
   * Bimodal benchmark factory function. Generates traffic with a 90% short vs.
   * 10% long request split for all clients
   */
  static std::pair<std::unique_ptr<Benchmark>, Err::SocketError> create_bimodal(std::string destIP, int port,
                                                                                unsigned numClients,
                                                                                std::vector<int> windowDurations,
                                                                                std::vector<int> windowThroughputs) {
    std::vector<std::unique_ptr<Client>> clients;

    for (unsigned i = 0; i < numClients; i++) {
      std::vector<double> probabilities = {0.9, 0.1};
      std::vector<unsigned char> serviceTimes = {DEFAULT_SERVICE_TIME, 10 * DEFAULT_SERVICE_TIME};
      auto generator = DiscreteValueGenerator<unsigned char>::create(probabilities, serviceTimes);

      auto clientRet = Client::create(destIP, port, std::move(generator));
      if (clientRet.second != Err::NoError) return {nullptr, clientRet.second};

      clients.push_back(std::move(clientRet.first));
    }

    return {std::make_unique<Benchmark>(std::move(clients), numClients * 2, windowDurations, windowThroughputs),
            Err::NoError};
  }

  static std::pair<std::unique_ptr<Benchmark>, Err::SocketError> create(std::string destIP, int port,
                                                                        unsigned numClients, int duration,
                                                                        int throughput) {
    std::vector<int> durations = {duration};
    std::vector<int> throughputs = {throughput};
    return create(destIP, port, numClients, durations, throughputs);
  }

  /// runs the benchmark
  void run() {
    startClients();
    for (unsigned i = 0; i < windowDurations.size(); i++) {
      executeWindow(windowDurations[i], windowThroughputs[i]);
      std::cout << "sent: " << packetsOut << ", recv: " << packetsIn << std::endl;
    }
    stopClients();
    writeResults("output");
  }

 private:
  std::vector<std::unique_ptr<Client>> clients;
  ThreadPool threadPool;
  std::vector<int> windowDurations;
  std::vector<int> windowThroughputs;

  uint64_t packetsOut = 0;
  uint64_t packetsIn = 0;

  std::pair<LatencyHistogramVec, LatencyHistogramVec> mergeClientHistograms() {
    LatencyHistogramVec rtt = clients[0]->getRoundtripHistogram();
    LatencyHistogramVec qd = clients[0]->getQueuingDelayHistogram();

    for (unsigned i = 1; i < clients.size(); i++) {
      rtt.mergeWith(clients[i]->getRoundtripHistogram());
      qd.mergeWith(clients[i]->getQueuingDelayHistogram());
    }

    return {rtt, qd};
  }

  void executeWindow(int duration, uint64_t throughput) {
    while (duration > 0) {
      updateClientThroughputs(throughput);
      for (auto& client : clients) {
        packetsOut += client->getSentPackets();
        packetsIn += client->getReceivedPackets();
      }
      duration--;
      sleep(1);
    }
  }

  void updateClientThroughputs(uint64_t newThroughput) {
    uint64_t rpsPerClient = newThroughput / clients.size();
    std::cout << "current Rps = " << newThroughput << "\n";
    for (auto& client : clients) {
      client->setThroughput(newThroughput);
      client->incrementTokens(rpsPerClient);
    }
  }

  /// starts all clients managed by the benchmark
  void startClients() {
    for (auto& client : clients) {
      client->start();
      threadPool.enqueue([&client] { client->sendLoop(); });
      threadPool.enqueue([&client] { client->recvLoop(); });
    }
  }

  /// stops all clients managed by the benchmark
  void stopClients() {
    for (auto& client : clients) {
      client->stop();
    }
  }

  void writeResults(std::string prefix) {
    auto histograms = mergeClientHistograms();
    histograms.first.writeToCSV(prefix + "_rtt.csv");
    histograms.second.writeToCSV(prefix + "_qd.csv");
  }
};

#endif
