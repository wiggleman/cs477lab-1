// SPDX-License-Identifier: MIT
#include <bpf/bpf.h>
#include <getopt.h>
#include <net/if.h>
#include <unistd.h>

#include <Benchmark.hpp>
#include <ClientBenchmarks.hpp>
#include <ProcParser.cpp>
#include <ProgramOptions.hpp>
#include <ServerBenchmark.hpp>
#include <iostream>
#include <string>
#include <vector>

namespace {

[[noreturn]] void Usage() {
  std::string logo =
      "   _____  _____ _  _ ______ ______   _               ____    __ \n"
      "  / ____|/ ____| || |____  |____  | | |        /\\   |  _ \\  /_ |\n"
      " | |    | (___ | || |_  / /    / /  | |       /  \\  | |_) |  | |\n"
      " | |     \\___ \\|__   _|/ /    / /   | |      / /\\ \\ |  _ <   | |\n"
      " | |____ ____) |  | | / /    / /    | |____ / ____ \\| |_) |  | |\n"
      "  \\_____|_____/   |_|/_/    /_/     |______/_/    \\_\\____/   |_|\n";

  std::cout << logo << std::endl;
  std::cout << std::endl << "bpfnic: BPF on SmartNICs" << std::endl;
  std::cout << "Options:" << std::endl;
  std::cout << "-h/--help: Print help" << std::endl;
  std::cout << "-m/--mode = <client/server>: decides whether to run client or server program" << std::endl;
  std::cout << "-p/--port: Port that server benchmark listens on" << std::endl;
  std::cout << "-d/--duration: duration of benchmark in seconds . Defaults to 60 secs" << std::endl;
  std::cout << std::endl;
  std::cout << "-n/--num_clients: number of clients in client benchmark" << std::endl;
  std::cout << "-a/--addr: ip address of the server (supports IPv4)" << std::endl;
  std::cout << "-D/--distribution = <bimodal/unimodal/debug>: distribution of client-generated traffic"
            << std::endl;
  std::cout << std::endl;
  std::cout << "-i/--ifname: network interface bpf program will be attached to" << std::endl;
  std::cout << "-P/--policy = <rr/rrcs/dca>: RSS policy for server benchmark" << std::endl;
  std::cout << "-c/--cpus: total number of cpus for server benchmark" << std::endl;
  std::cout << "-R/--reserved_long: number of cores reserved for long requests (core separated policy)" << std::endl;
  std::cout << std::endl << "Report any bugs to RS3Lab <rs3lab@groupes.epfl.ch>" << std::endl;
  std::exit(1);
}

}  // namespace

int doServerBenchmark(ProgramOptions& programOpts);
void doClientBenchmark(ProgramOptions& programOpts);

int main(int argc, char *argv[]) {
  int opt;
  ProgramOptions programOpts;
  struct option longOptions[] = {
      {"help", optional_argument, 0, 'h'},
      {"mode", required_argument, 0, 'm'},
      {"port", required_argument, 0, 'p'},
      {"duration", required_argument, 0, 'd'},

      /* required by server benchmark */
      {"ifname", optional_argument, 0, 'i'},
      {"cpus", optional_argument, 0, 'c'},
      {"policy", optional_argument, 0, 'P'},
      {"reserved_long", optional_argument, 0, 'R'},

      /* used by client benchmark */
      {"num_clients", optional_argument, 0, 'n'},
      {"addr", optional_argument, 0, 'a'},
      {"distribution", optional_argument, 0, 'D'},

      {0, 0, 0, 0},
  };

  while ((opt = getopt_long(argc, argv, "h:m:p:d:i:c:P:R:n:a:v:T:D:S:I:t:", longOptions, NULL)) != -1) {
    switch (opt) {
      case 'h':
        Usage();
        break;
      case 'm':
        programOpts.mode = optarg;
        break;
      case 'p':
        programOpts.port = std::stoi(optarg);
        break;
      case 'd':
        programOpts.duration = std::stoi(optarg);
        break;
      case 'i':
        programOpts.ifname = optarg;
        break;
      case 'c':
        programOpts.numCpus = std::stoi(optarg);
        break;
      case 'P':
        programOpts.serverPolicy = optarg;
        break;
      case 'R':
        programOpts.numLongCpus = std::stoi(optarg);
        break;
      case 'n':
        programOpts.numClients = std::stoi(optarg);
        break;
      case 'a':
        programOpts.serverIP = optarg;
        break;
      case 'D':
        programOpts.distribution = optarg;
        break;
      default:
        Usage();
        break;
    }
  }

  if (!programOpts.hasNecessaryOpts()) Usage();

  if (programOpts.isServerBench())
    doServerBenchmark(programOpts);
  else if (programOpts.isClientBench())
    doClientBenchmark(programOpts);
  else
    Usage();
}

void doClientBenchmark(ProgramOptions& programOpts) {
  if (programOpts.distribution == CLIENT_MODE_BIMODAL)
    bimodalIncreasingBenchmark(programOpts.serverIP, programOpts.port, programOpts.numClients);
  else if (programOpts.distribution == CLIENT_MODE_UNIMODAL)
    unimodalIncreasingBenchmark(programOpts.serverIP, programOpts.port, programOpts.numClients);
  else if (programOpts.distribution == CLIENT_MODE_DEBUG)
    debugBenchmark(programOpts.serverIP, programOpts.port, programOpts.numClients);
  else
    Usage();
}

int doServerBenchmark(ProgramOptions& programOpts) {
  std::cout << "server benchmark" << std::endl;
  if (programOpts.serverPolicy == std::string(POLICY_ROUNDROBIN)) {
    std::cout << "Launching round-robin without core-separation" << std::endl;
    std::vector<int> cpus;
    for (int i = 0; i < programOpts.numCpus; i++) cpus.push_back(i);
    return redirectProgRoundRobin(cpus, programOpts.ifname, programOpts.port, programOpts.duration);

  } else if (programOpts.serverPolicy == std::string(POLICY_ROUNDROBIN_CORE_SEP)) {
    std::cout << "Launching round-robin with core-separation" << std::endl;
    std::vector<int> cpusShort;
    std::vector<int> cpusLong;

    for (int i = 0; i < programOpts.numCpus - programOpts.numLongCpus; i++) cpusShort.push_back(i);

    for (int i = programOpts.numCpus - programOpts.numLongCpus; i < programOpts.numCpus; i++) cpusLong.push_back(i);

    std::cout << "short reserved cpus: [";
    for (auto cpu : cpusShort) {
      std::cout << cpu << ", ";
    }
    std::cout << "]" << std::endl;

    std::cout << "long reserved cpus: [";
    for (auto cpu : cpusLong) {
      std::cout << cpu << ", ";
    }
    std::cout << "]" << std::endl;
    return redirectProgRoundRobinCoreSeparated(cpusShort, cpusLong, programOpts.ifname, programOpts.port,
                                               programOpts.duration);

  } else if (programOpts.serverPolicy == std::string(POLICY_DYNAMIC_CORE_ALLOC)) {
    std::cout << "Launching dynamic core allocation prog" << std::endl;
    std::vector<int> cpus;
    for (int i = 0; i < programOpts.numCpus; i++) cpus.push_back(i);
    return redirectProgDynamicCoreAllocation(cpus, programOpts.ifname, programOpts.port, programOpts.duration);
  } else {
    Usage();
  }
}
