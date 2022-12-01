// platform-independent implementations of functions from 'bcnet.h'
#include "bcnet/bcnet.h"

#if defined(_WIN32) || defined(__WIN32__)
# include <WinSock2.h>
#else
# include <unistd.h>
# include <sys/socket.h>
# define closesocket close
#endif

#include <stdio.h>
#include <malloc.h>

bcn_socket_t create_socket() {
  bcn_socket_t bcn_socket = (bcn_socket_t){ 0 };
  bcn_socket.fd = socket(AF_INET, SOCK_DGRAM, 0);
  bcn_socket.convKey = 0;
  bcn_socket.curTarget = 0;
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

send_content(bcn_socket_t* bcn_socket, char* buffer, int32_t bufSize, Key target, struct sockaddr_in* addrChunk) {
  if (bcn_socket->streamPacketsSent > 0) {
    bcn_socket->streamPacketsSent = 0;
    bcn_socket->convKey = 0;
    bcn_socket->curTarget = 0;
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
  memcpy_s(body, bufSize, buffer, bufSize);

  // TODO encrypt the packet

  // brodcast the packet
  struct sockaddr_in tempaddr = *addrChunk;
  for (tempaddr.sin_addr.S_un.S_un_w.s_w2 = 0; tempaddr.sin_addr.S_un.S_un_w.s_w2 <= USHRT_MAX; tempaddr.sin_addr.S_un.S_un_w.s_w2++) {
    sendto(bcn_socket, packet, packetSize, 0, &tempaddr, sizeof(struct sockaddr)); // TODO do we need to cast tempaddr to a struct sockaddr?
  }

  free(packet);
  return 0;
}