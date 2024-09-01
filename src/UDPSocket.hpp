/**
 * UDPSocket.hpp - UDP socket that exposes API for sending and receiving UDP
 * packets
 * Author: Ethan Graham
 */
#ifndef UDPSOCKET_H
#define UDPSOCKET_H

#include <netinet/in.h>

#include <memory>
#include <string>
#include <utility>

#include "../common/packet.h"

namespace Err {
enum SocketError { NoError = 0, SocketFdFailure, SocketBindFailure, UDPFailure, InvalidPacket };
}

class UDPSocket {
 private:
  struct sockaddr_in destAddr;
  struct sockaddr_in srcAddr;
  int sockfd;
  char *recvBuff;
  size_t recvBufferSize;

 public:
  UDPSocket(int sockfd, struct sockaddr_in destAddr, struct sockaddr_in srcAddr);
  ~UDPSocket();

  /**
   * Socket Factory
   *
   * @returns a UDPClient with no error on success, or a nullopt and/or
   * SocketError on failure
   */
  static std::pair<std::unique_ptr<UDPSocket>, Err::SocketError> create(const std::string& destIp, int port);

  /**
   * Sends a packet to the socket's destination address.
   * @returns NoError = 0 on success, UDPFailure on failure
   */
  Err::SocketError sendPacket(struct packet *packet);

  /**
   * Gets a packet into the socket's recvBuffer. This is blocking
   *
   * @returns {bytesRead, NoError} on success, {_, SocketError} on failure
   */
  std::pair<size_t, Err::SocketError> recvPacket();

  /**
   * @returns a pointer to the start of the recvBuffer. In combination with
   * recvPacket(), allows us to get a pointer and range to the socket's
   * buffer without needing to copy.
   */
  char *getRecvBuffer();

  /**
   * @returns the content of the receive buffer as a string.
   */
  std::string getBufferContent();
};

#endif
