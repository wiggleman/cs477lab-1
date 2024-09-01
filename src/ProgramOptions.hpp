/**
 * ProgramOptions.hpp
 * Author: Ethan Graham
 */
#ifndef PROGRAM_OPTS_H
#define PROGRAM_OPTS_H

#include <string>

#define POLICY_ROUNDROBIN "rr"
#define POLICY_ROUNDROBIN_CORE_SEP "rrcs"
#define POLICY_DYNAMIC_CORE_ALLOC "dca"

#define CLIENT_MODE_BIMODAL "bimodal"
#define CLIENT_MODE_UNIMODAL "unimodal"
#define CLIENT_MODE_DEBUG "debug"
#define CLIENT_MODE_BURSTY "bursty"

#define REQUIRE_NON_EMPTY(s) \
  if (s.empty()) return false;

#define REQUIRE_STRICTLY_POSITIVE(i) \
  if (i <= 0) return false;

#define REQUIRE_POSITIVE(i) \
  if (i < 0) return false;

/**
 * Defines the set of program options
 */
struct ProgramOptions {
  int port = 50'000;
  int duration = 60;
  int numCpus = -1;
  int numLongCpus = -1;
  int numClients = 5;
  std::string mode;
  std::string serverPolicy;
  std::string ifname;
  std::string serverIP;
  std::string distribution;

 public:
  bool isServerBench() { return mode == "server"; }
  bool isClientBench() { return mode == "client"; }

  /**
   * returns `true` if the program has all necessary options set
   */
  bool hasNecessaryOpts() {
    if (isServerBench())
      return hasNecessaryOptsServer();
    else if (isClientBench())
      return hasNecessaryOptsClient();
    else
      return false;
  }

 private:
  /**
   * Returns `true` iff the server program has all necessary options
   */
  bool hasNecessaryOptsServer() {
    REQUIRE_NON_EMPTY(serverPolicy);
    REQUIRE_NON_EMPTY(ifname);
    REQUIRE_STRICTLY_POSITIVE(port);
    REQUIRE_STRICTLY_POSITIVE(numCpus);
    REQUIRE_STRICTLY_POSITIVE(duration);

    if (serverPolicy == POLICY_ROUNDROBIN_CORE_SEP) {
      REQUIRE_STRICTLY_POSITIVE(numLongCpus);
    }

    return true;
  }

  /**
   * Returns `true` iff the client program has all necessary options
   */
  bool hasNecessaryOptsClient() {
    REQUIRE_NON_EMPTY(serverIP);
    REQUIRE_STRICTLY_POSITIVE(port);
    REQUIRE_NON_EMPTY(distribution);
    REQUIRE_POSITIVE(port);
    REQUIRE_STRICTLY_POSITIVE(duration);
    REQUIRE_STRICTLY_POSITIVE(numClients);

    return true;
  }
};
#endif
