#ifndef PROC_PARSER
#define PROC_PARSER

#include <unistd.h>

#include <algorithm>
#include <complex>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#define SLASH_PROC "/proc"
#define STATUS "status"
#define STAT "stat"

namespace fs = std::filesystem;

struct StatContents {
  unsigned long stime;
  unsigned long long starttime;
};

struct MemoizedData {
  unsigned long cyclesCounted;  // How many cycles have already been counted (to avoid double-counting)
  unsigned long prevProbe;      // When the PID was last probed. Measured in clock ticks since boot
};

/**
 * Parses `PID` files in the `/proc` directory
 */
class ProcParser {
 private:
  std::string keyWord;          // the keyword that is searched for
  std::vector<int> pidMatches;  // PIDs whose name contains keyword
                                // maps pid to an accumulator corresponding to the cycles already counted
                                // for a given pid
  std::unordered_map<int, unsigned long long> cycleAccumulators;

  // Maps pid to some memoized data
  std::unordered_map<int, MemoizedData> memoizedDataMap;

  static bool fileExists(fs::path& targetFilePath) {
    return fs::exists(targetFilePath) && fs::is_regular_file(targetFilePath);
  }

  /**
   * Searches for directories `/proc/[PID]` whose status file contains has a
   * Name containing `keyWord` as substring
   */
  void searchForMatchingPids() {
    pidMatches.clear();
    auto directoryIter = fs::directory_iterator(SLASH_PROC);

    for (auto processEntry : directoryIter) {
      std::string fileName = processEntry.path().filename();
      // check that the directory is indeed a directoryfileName.
      if (!processEntry.is_directory()) continue;
      // check that the directory contains only digits (as a PID should)
      if (!std::all_of(fileName.begin(), fileName.end(), ::isdigit)) continue;
      // check that the status file exists
      fs::path statusPath = processEntry.path() / STATUS;
      if (!fileExists(statusPath)) continue;

      int pid = std::stoi(fileName);
      if (statusFileContainsKeyWord(statusPath)) {
        pidMatches.push_back(pid);
      }
    }
  }

  bool statusFileContainsKeyWord(const fs::path& filePath) {
    std::string line;

    std::ifstream file(filePath);
    if (!file.is_open()) return false;

    std::getline(file, line);
    file.close();

    return line.find(keyWord) != std::string::npos;
  }

  /**
   * Parses the contnts of stat into an instance of `StatContents`
   */
  StatContents parseStat(std::string& statContents) {
    int stimeIdx = 14;
    int starttimeIdx = 21;

    std::istringstream iss(statContents);
    std::vector<std::string> tokens(std::istream_iterator<std::string>{iss}, std::istream_iterator<std::string>());

    unsigned long stime = std::stoul(tokens.at(stimeIdx));
    unsigned long long starttime = std::stoull(tokens.at(starttimeIdx));

    StatContents stat{.stime = stime, .starttime = starttime};
    return stat;
  }

  /**
   * Parses the contents of `/proc/[pid]/stat` as `StatContents`
   * @return `nullopt` on failure
   */
  std::optional<StatContents> readStat(int pid) {
    fs::path procPath = SLASH_PROC;
    fs::path statPath = procPath / std::to_string(pid);
    statPath = statPath / STAT;

    std::string line;
    std::ifstream file(statPath);
    if (!file.is_open()) return std::nullopt;

    std::getline(file, line);
    file.close();

    return parseStat(line);
  }

  /**
   * @return the number of clock ticks since boot (accurate to the second) or
   * `nullopt` on failure.
   */
  std::optional<unsigned long> getUptimeTicks() {
    fs::path procPath = SLASH_PROC;
    fs::path uptimePath = procPath / std::string("uptime");

    std::ifstream file(uptimePath);
    if (!file.is_open()) {
      std::cerr << "Could not open /proc/uptime" << std::endl;
      return std::nullopt;
    }

    std::string line;
    std::getline(file, line);
    file.close();

    std::stringstream ss(line);
    double uptimeSeconds, idleSeconds;
    ss >> uptimeSeconds >> idleSeconds;

    return (unsigned long)uptimeSeconds * sysconf(_SC_CLK_TCK);
  }

  // @return cpu utilization of a process with pid `pid` since the last probe as a fraction between [0, 1]
  std::optional<double> computeCpuUtilization(int pid) {
    auto statContentsOpt = readStat(pid);
    if (statContentsOpt == std::nullopt) return std::nullopt;
    StatContents statContents = statContentsOpt.value();

    // get memoized data for this process or insert it
    MemoizedData memoizedData;
    auto itValue = memoizedDataMap.find(pid);
    if (itValue != memoizedDataMap.end())
      memoizedData = itValue->second;
    else {
      MemoizedData defaultVal = {.cyclesCounted = 0, .prevProbe = statContents.starttime};
      memoizedDataMap.insert(std::make_pair(pid, defaultVal));
      memoizedData = defaultVal;
    }

    auto currUptime = getUptimeTicks();
    if (currUptime == std::nullopt) return std::nullopt;

    long activeTicksInWindow = statContents.stime - memoizedData.cyclesCounted;
    long totalTicksInWindow = currUptime.value() - memoizedData.prevProbe;

    memoizedData.prevProbe = currUptime.value();
    memoizedData.cyclesCounted = statContents.stime;
    memoizedDataMap[pid] = memoizedData;

    if (activeTicksInWindow > totalTicksInWindow) {
      std::cout << "\033[33mWarning: active ticks > total ticks! pid = " << pid << "\033[0m" << std::endl;
      return 1.0;
    }

    return ((double)activeTicksInWindow / (double)totalTicksInWindow);
  }

 public:
  ProcParser(const char *keyWord) : keyWord(std::string(keyWord)), pidMatches(std::vector<int>()) {}

  ~ProcParser() {}

  void readStatLines() {
    for (int pid : pidMatches) readStat(pid);
  }

  /**
   * Computes cpu utilitazion since the last query of every process in `/proc`
   * containing `keyWord` in its process name
   * @returns a vector of doubles in [0.0, 1.0] of CPU utilizations in the
   * order that they were parsed from /proc
   */
  std::vector<double> getCpuUtilizationVec() {
    std::vector<double> output;
    searchForMatchingPids();
    for (int pid : pidMatches) {
      auto utilization = computeCpuUtilization(pid);
      if (utilization == std::nullopt) std::cerr << "Failed to compute utilization for pid=" << pid << std::endl;
      output.push_back(utilization.value());
    }
    return output;
  }

  /**
   * @return the average cpu utilization of associated processes
   *
   * Note: this resets memoized state when called - thus is should only be
   * called once per window.
   */
  double computeAverageCpuUtilization() {
    auto cpuUtilizations = getCpuUtilizationVec();
    double avgUtilization = 0.0;
    int nonZeroUtilizationsCount = 0;

    for (double cpuUtilization : cpuUtilizations) {
      avgUtilization += cpuUtilization;
      if (cpuUtilization > 0) nonZeroUtilizationsCount++;
    }

    if (nonZeroUtilizationsCount > 0) return avgUtilization /= nonZeroUtilizationsCount;
    return 0;
  }

  const std::string getKeyWord() const { return keyWord; }
};
#endif
