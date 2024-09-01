#ifndef _DISCRETE_VALUE_GENERATOR_H
#define _DISCRETE_VALUE_GENERATOR_H

/**
 * Generates packets via some distribution
 */
#include <memory>
#include <random>
#include <vector>

/**
 * @brief a thin wrapper around a discrete random generator of type T
 */
template <typename T>
class DiscreteValueGenerator {
 public:
  DiscreteValueGenerator(std::vector<double> probabilities, std::vector<T> values,
                         unsigned int seed = std::random_device{}())
      : probs(probabilities),
        values(values),
        gen(seed),
        dist(std::discrete_distribution<>(probabilities.begin(), probabilities.end())) {}

  static std::unique_ptr<DiscreteValueGenerator<T>> create(std::vector<double> probabilities, std::vector<T> values,
                                                           unsigned int seed = std::random_device{}()) {
    if (probabilities.size() != values.size()) return nullptr;

    return std::make_unique<DiscreteValueGenerator>(probabilities, values, seed);
  }

  T generate() { return values[dist(gen)]; }

 private:
  std::vector<double> probs;
  std::vector<T> values;

  std::mt19937 gen;
  std::discrete_distribution<> dist;
};

#endif
