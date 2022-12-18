// platform-independent implementations of functions from 'bcnet.h'
#include "bcnet/bcnet.h"

#if defined(_WIN32) || defined(__WIN32__)
# include <WinSock2.h>
#else
# include <unistd.h>
# include <sys/socket.h>
#include <netdb.h>
# define closesocket close
#endif

#include <stdio.h>
#include <stddef.h>
#include <malloc.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

bcn_socket_t create_socket() {
  bcn_socket_t bcn_socket = (bcn_socket_t){ 0 };
  bcn_socket.fd = socket(AF_INET, SOCK_DGRAM, 0);
  // convKey & curTarget are arrays, so they're already initilized
  bcn_socket.streamPacketsSent = 0;
  return bcn_socket;
}

destroy_socket(bcn_socket_t* bcn_socket) {
  int result;
  if ((result = closesocket(bcn_socket->fd)) != 0) {
    return result;
  }
  memset(bcn_socket, 0, sizeof(bcn_socket_t));
  return 0;
}

send_content(bcn_socket_t* bcn_socket, char* buffer, int32_t bufSize, struct sockaddr_bcn target) {
  if (bcn_socket->streamPacketsSent > 0) { // stream sockets sending content packets will lose their connection to the stream
    bcn_socket->streamPacketsSent = 0;
    memset(bcn_socket->convKey, 0, sizeof(key_t));
    memset(bcn_socket->curTarget, 0, sizeof(key_t));
  }

  size_t packetSize = sizeof(struct bcn_packet_header) + bufSize;
  char *packet = malloc(packetSize);

  // populate the header
  struct bcn_packet_header *header = (struct bcn_packet_header*)packet;
  *header = (struct bcn_packet_header){ .constant = BNP_CONST };
  header->content_length = bufSize;
  header->type = CONTENT;
  header->order = 0;

  // populate the body
  char* body = packet + sizeof(struct bcn_packet_header);
  if (!rsa_encrypt(target.key, buffer, bufSize, body, sizeof(body))) {
    return -1; // errno should be set by rsa_encrypt
  }

  // brodcast the packet
  struct sockaddr_in tempaddr = {
    .sin_family = AF_INET,
    .sin_addr = {
      .s_addr = target.range.full << 16
    },
    .sin_port = target.port,
    .sin_zero = {0,0,0,0,0,0,0,0}
  };
  for (uint16_t lastIpHalf = 0; lastIpHalf <= UINT16_MAX; lastIpHalf++) {
    tempaddr.sin_addr.s_addr++;
    sendto(bcn_socket, packet, packetSize, 0, &tempaddr, sizeof(struct sockaddr)); // TODO do we need to cast tempaddr to a struct sockaddr?
  }

  free(packet);
  return 0;
}

recv_content(bcn_socket_t* bcn_socket, char* buffer, int32_t bufsize, struct sockaddr_bcn fromaddr) {
  if (bcn_socket->streamPacketsSent > 0) { // stream sockets sending content packets will lose their connection to the stream
    bcn_socket->streamPacketsSent = 0;
    memset(bcn_socket->convKey, 0, sizeof(key_t));
    memset(bcn_socket->curTarget, 0, sizeof(key_t));
  }

  int result = 0;

  // recieve the packet
  struct sockaddr_in tempaddr = {
    .sin_family = AF_INET,
    .sin_addr = {
      .s_addr = fromaddr.range.full << 16
    },
    .sin_port = fromaddr.port,
    .sin_zero = {0,0,0,0,0,0,0,0}
  };
  size_t packetsize = bufsize + sizeof(struct bcn_packet_header);
  char *encryptedpacket = malloc(packetsize);
  for (uint16_t lastIpHalf = 0; lastIpHalf <= UINT16_MAX; lastIpHalf++) {
    tempaddr.sin_addr.s_addr++;
    result = recvfrom(bcn_socket->fd, encryptedpacket, packetsize, 0, &tempaddr, sizeof(tempaddr)); // TODO do we need to cast tempaddr to a struct sockaddr?

    // check if the packet is ours
    if (result < sizeof(struct bcn_packet_header)) {
      continue;
    }
    rsa_decrypt(fromaddr.key, encryptedpacket, packetsize, buffer, bufsize);
    struct bcn_packet_header *header = (struct bcn_packet_header*)buffer;
    if (header->constant != BNP_CONST) {
      memset(buffer, 0, bufsize); // TODO is this the right order?
      continue;
    }
    if (header->type != CONTENT) {
      memset(buffer, 0, bufsize); // TODO is this the right order?
      continue;
    }

    // get the message content
  }
  free(encryptedpacket);

  return result;
}
