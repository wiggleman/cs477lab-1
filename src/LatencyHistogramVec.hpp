#ifndef _LATENCY_HISTOGRAM_VEC_H
#define _LATENCY_HISTOGRAM_VEC_H

#include <stdint.h>

#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

/**
 * defines a latency measurement - throughput and serviceTime are taken as
 * labels and are configurable by the client.
 */
struct LabelValues {
  uint64_t throughput;
  uint8_t serviceTime;

  bool operator==(const LabelValues& other) const {
    return throughput == other.throughput && serviceTime == other.serviceTime;
  }
};

/**
 * Defines a series of latency histograms labeled by throughput and service
 * time.
 * This data structure is NOT thread safe - the idea is that each client will
 * maintain their own version, and some main thread will merge them together
 * in the post-processing stage before writing them out.
 */
class LatencyHistogramVec {
 public:
  LatencyHistogramVec(long bucketWidthNanos = 1000 /* 1us */) : bucketWidthNanos(bucketWidthNanos) {}

  ~LatencyHistogramVec(){};

  // increments the histogram entry for a recorded measurement
  void increment(LabelValues measurement, long nanos) {
    int idx = getEntryIdx(measurement);
    if (idx < 0) {
      addEntry(measurement);
      idx = labels.size() - 1;
    }

    long roundedNanos = (nanos / bucketWidthNanos) * bucketWidthNanos;
    histogramVec[idx][roundedNanos]++;
  }

  // writes the histogram out as a .csv. Returns -1 on failure, number of rows
  // written (excl. the header row) on success
  int writeToCSV(std::string filename) {
    std::ofstream file(filename);

    if (!file.is_open()) {
      return -1;
    }

    file << "nanos,count,throughput,srv_time\n";

    int rows = 0;
    for (unsigned i = 0; i < labels.size(); i++) {
      LabelValues label = labels[i];
      auto hist = histogramVec[i];

      for (auto bucketCount : hist) {
        auto bucket = bucketCount.first;
        auto count = bucketCount.second;

        file << bucket << "," << count << "," << label.throughput << "," << (int)label.serviceTime << "\n";
        rows++;
      }
    }

    file.close();
    return rows;
  }

  // Merges the current histogram with another histogram - i.e. increments all
  // counts by those found in other, and adds any values that do not exist in
  // this histogram.
  // It is a requirement that both latency histograms have the same label
  // values sequence - this is checked at runtime.
  int mergeWith(const LatencyHistogramVec& other) {
    if (labels.size() != other.labels.size()) return -1;

    for (unsigned i = 0; i < labels.size(); i++) {
      if (labels[i] != other.labels[i]) return -1;
    }

    for (unsigned i = 0; i < histogramVec.size(); i++) {
      std::unordered_map<long, long>& thisHist = histogramVec[i];
      const std::unordered_map<long, long>& otherHist = other.histogramVec[i];

      for (auto bucketCount : otherHist) {
        long bucket = bucketCount.first;
        long count = bucketCount.second;

        thisHist[bucket] += count;
      }
    }

    return 0;
  }

  const std::vector<LabelValues> getLabelValues() { return labels; }

 private:
  std::vector<std::unordered_map<long, long>> histogramVec;
  std::vector<LabelValues> labels;
  int bucketWidthNanos;

  // inserts a new entry at the end of the histogram vec
  void addEntry(LabelValues measurement) {
    labels.push_back(measurement);
    histogramVec.emplace_back();
  }

  // returns the index of the entry with the provided label values, or -1 if
  // it does not exist
  int getEntryIdx(LabelValues measurement) {
    for (unsigned i = 0; i < labels.size(); i++) {
      if (labels[i] == measurement) return i;
    }
    return -1;
  }
};

#endif
