#ifndef _CLIENT_H
#define _CLIENT_H

#include <DiscreteValueGenerator.hpp>
#include <LatencyHistogramVec.hpp>
#include <UDPSocket.hpp>
#include <atomic>
#include <chrono>
#include <iostream>

#define DEFAULT_SERVICE_TIME 1  // 1us

/**
 * Defines a Client, which manages the generation of variable throughput
 * traffic via a UDP socket, and maintains a histogram of queuing delays and
 * round-trip times
 *
 * The token bucket algorithm is used for rate limiting
 */
class Client {
 public:
  /// @brief constructor without explicit service time distribution
  Client(std::unique_ptr<UDPSocket> sock)
      : udpSocket(std::move(sock)),
        stopFlag(false),
        numSentPackets(0),
        numReceivedPackets(0),
        tokenBucket(std::make_unique<std::atomic<uint64_t>>(0)),
        serviceTimeGenerator(DiscreteValueGenerator<unsigned char>::create(
            std::vector<double>{1.0}, std::vector<unsigned char>{DEFAULT_SERVICE_TIME})) {}

  /// @brief constructor with explicit service time distribution
  Client(std::unique_ptr<UDPSocket> sock, std::unique_ptr<DiscreteValueGenerator<unsigned char>> serviceTimeGenerator)
      : udpSocket(std::move(sock)),
        stopFlag(false),
        numSentPackets(0),
        numReceivedPackets(0),
        tokenBucket(std::make_unique<std::atomic<uint64_t>>(0)),
        serviceTimeGenerator(std::move(serviceTimeGenerator)) {}

  /**
   * @return unique_ptr to a Client with default service time generator on
   * success, or a SocketError on failure
   */
  static std::pair<std::unique_ptr<Client>, Err::SocketError> create(const std::string destIP, int port) {
    auto socketRet = UDPSocket::create(destIP, port);
    if (socketRet.second != Err::NoError) return {nullptr, socketRet.second};

    return {std::make_unique<Client>(std::move(socketRet.first)), Err::NoError};
  }

  /**
   * @return unique_ptr to a Client with a user-defined service time generator
   * on success, or a SocketError on failure
   */
  static std::pair<std::unique_ptr<Client>, Err::SocketError> create(
      const std::string destIP, int port, std::unique_ptr<DiscreteValueGenerator<unsigned char>> serviceTimeGenerator) {
    auto socketRet = UDPSocket::create(destIP, port);
    if (socketRet.second != Err::NoError) return {nullptr, socketRet.second};

    return {std::make_unique<Client>(std::move(socketRet.first), std::move(serviceTimeGenerator)), Err::NoError};
  }

  /// @brief set the distribution. Allows for runtime reques distribution
  /// changes
  void setServiceTimeDistribution(std::unique_ptr<DiscreteValueGenerator<unsigned char>> newDistribution) {
    serviceTimeGenerator = std::move(newDistribution);
  }

  void start() { stopFlag = false; }
  void stop() { stopFlag = true; }

  void recvLoop() {
    while (!stopFlag) {
      numReceivedPackets++;
      if (recvAndProcessPacket() != Err::NoError) std::cerr << "Invalid packet format...\n";
    }
  }

  void sendLoop() {
    while (!stopFlag) {
      if (tokenBucket->load() <= 0) continue;
      tokenBucket->fetch_sub(1);

      if (genAndSendPacket() == Err::NoError)
        numSentPackets++;
      else
        // TODO add more robust handling here instead of just printing
        std::cout << "error sending packet" << std::endl;
    }
  }

  /// @return the number of send packets
  size_t getSentPackets() {
    size_t ret = numSentPackets;
    numSentPackets = 0;
    return ret;
  }

  /// @return the number of received packets
  size_t getReceivedPackets() {
    size_t ret = numReceivedPackets;
    numReceivedPackets = 0;
    return ret;
  }

  LatencyHistogramVec getRoundtripHistogram() { return roundTripHistogram; }

  LatencyHistogramVec getQueuingDelayHistogram() { return queuingDelayHistogram; }

  void incrementTokens(uint64_t by) { tokenBucket->fetch_add(by); }
  void setThroughput(uint64_t newThroughput) { throughputRps = newThroughput; }

 private:
  std::unique_ptr<UDPSocket> udpSocket;
  volatile bool stopFlag;
  size_t numSentPackets;
  size_t numReceivedPackets;

  LatencyHistogramVec roundTripHistogram;
  LatencyHistogramVec queuingDelayHistogram;

  // finite bucket of tokens used for rate limiting
  std::unique_ptr<std::atomic<uint64_t>> tokenBucket;
  // generates service times
  std::unique_ptr<DiscreteValueGenerator<unsigned char>> serviceTimeGenerator;

  uint64_t throughputRps;

  /// @return a high-resolution timestamp in nanoseconds
  uint64_t getTimeStamp() {
    auto currTime = std::chrono::high_resolution_clock::now();
    auto nanos = std::chrono::time_point_cast<std::chrono::nanoseconds>(currTime).time_since_epoch();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(nanos).count();
  }

  Err::SocketError recvAndProcessPacket() {
    auto recvRet = udpSocket->recvPacket();
    if (recvRet.second != Err::NoError) return recvRet.second;
    int bytesReceived = recvRet.first;
    if (bytesReceived != sizeof(struct packet)) return Err::InvalidPacket;

    /// interpret the element in the receive buffer as a packet
    struct packet *p = (struct packet *)udpSocket->getRecvBuffer();

    uint64_t roundtripNanos = getTimeStamp() - p->leave_client_timestamp;
    uint64_t queuingDelayNanos = p->leave_server_timestamp - p->reach_server_timestamp;

    LabelValues l = {
        .throughput = throughputRps,
        .serviceTime = p->data,
    };

    roundTripHistogram.increment(l, roundtripNanos);
    queuingDelayHistogram.increment(l, queuingDelayNanos);

    return Err::NoError;
  }

  /**
   * @brief generates and sends a packet over the UDP socket
   *
   * @return the return value from the UDP socket
   */
  Err::SocketError genAndSendPacket() {
    struct packet p = {
        .leave_client_timestamp = getTimeStamp(),
        .data = serviceTimeGenerator->generate(),
    };
    return udpSocket->sendPacket(&p);
  }
};

#endif
