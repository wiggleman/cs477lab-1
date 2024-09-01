/**
 * Client.cpp - Client and Socket classes
 * Author: Ethan Graham
 */
#include "UDPSocket.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <memory>
#include <string>

#define RECV_BUFFER_LEN 1024

UDPSocket::UDPSocket(int sockfd, struct sockaddr_in destAddr, struct sockaddr_in srcAddr)
    : destAddr(destAddr),
      srcAddr(srcAddr),
      sockfd(sockfd),
      recvBuff(new char[RECV_BUFFER_LEN]),
      recvBufferSize(RECV_BUFFER_LEN) {}

UDPSocket::~UDPSocket() {
  std::cout << "destroying socket\n";
  close(sockfd);
}

std::pair<std::unique_ptr<UDPSocket>, Err::SocketError> UDPSocket::create(const std::string& destIp, int port) {
  int sockfd;
  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    return {nullptr, Err::SocketFdFailure};
  }

  int disable = 1;
  setsockopt(sockfd, SOL_SOCKET, SO_NO_CHECK, (void *)&disable, sizeof(disable));

  struct sockaddr_in srcAddr = {0};
  srcAddr.sin_family = AF_INET;
  srcAddr.sin_port = htons(INADDR_ANY);
  srcAddr.sin_addr.s_addr = INADDR_ANY;

  if (bind(sockfd, (struct sockaddr *)(&srcAddr), sizeof(srcAddr)) < 0) {
    return {nullptr, Err::SocketBindFailure};
  }

  struct sockaddr_in addressPrint;
  socklen_t len = sizeof(addressPrint);
  getsockname(sockfd, (struct sockaddr *)&addressPrint, &len);

  char ip_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(addressPrint.sin_addr), ip_str, INET_ADDRSTRLEN);

  struct sockaddr_in destAddr;
  memset(&destAddr, 0, sizeof(destAddr));
  destAddr.sin_family = AF_INET;
  destAddr.sin_port = htons(port);
  destAddr.sin_addr.s_addr = inet_addr(destIp.c_str());

  auto ptr = std::make_unique<UDPSocket>(sockfd, destAddr, srcAddr);
  return {std::move(ptr), Err::NoError};
}

Err::SocketError UDPSocket::sendPacket(struct packet *packet) {
  int ret =
      sendto(sockfd, (const void *)packet, sizeof(struct packet), 0, (struct sockaddr *)&destAddr, sizeof(destAddr));

  if (ret < 0) {
    return Err::UDPFailure;
  }

  return Err::NoError;
}

std::pair<size_t, Err::SocketError> UDPSocket::recvPacket() {
  int bytesReceived;
  if ((bytesReceived = recv(sockfd, recvBuff, recvBufferSize, 0x0)) < 0) {
    return {0, Err::UDPFailure};
  }
  return {bytesReceived, Err::NoError};
}

char *UDPSocket::getRecvBuffer() { return recvBuff; }

std::string UDPSocket::getBufferContent() {
  std::string ret(recvBuff, recvBufferSize);
  return ret;
}
