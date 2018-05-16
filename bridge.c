#define CHIF_NET_IMPLEMENTATION
#include "chif/chif_net.h"

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

// ============================================================ //

void report_success_or_die(chif_net_result res, char* msg)
{
  if (res == CHIF_NET_RESULT_SUCCESS) {
    printf("[chif_net] %s\n", msg);
  }
  else {
    printf("[chif_net] FATAL %d: %s\n", res, msg);
    exit(1);
  }
}

chif_net_socket wait_for_connection(uint16_t port)
{
  printf("\n~ wait for connection ~\n");
  chif_net_socket sock;
  chif_net_protocol proto = CHIF_NET_PROTOCOL_TCP;
  chif_net_address_family fam = CHIF_NET_ADDRESS_FAMILY_IPV4;

  chif_net_result res = chif_net_open_socket(&sock, proto, fam);
  report_success_or_die(res, "open server socket");

  res = chif_net_set_reuse_addr(sock, true);
  report_success_or_die(res, "reuse addr");

  res = chif_net_bind(sock, port, fam);
  report_success_or_die(res, "bind server");

  res = chif_net_listen(sock, CHIF_NET_DEFAULT_MAXIMUM_BACKLOG);
  report_success_or_die(res, "listen");

  chif_net_address cli_addr;
  printf("[chif_net] waiting for client to connect\n");
  chif_net_socket cli_sock = chif_net_accept(sock, &cli_addr);
  if (cli_sock == CHIF_NET_INVALID_SOCKET) {
    printf("[chif_net] FATAL: accept client, entering_bridge_mode");
    exit(1);
  }
  printf("accept client, entering_bridge_mode\n");

  res = chif_net_close_socket(&sock);
  report_success_or_die(res, "closed server socket");

  return cli_sock;
}

void bridge_connection(chif_net_socket* sock, const char* target_ip, uint16_t target_port)
{
  printf("\n~ bridge connection ~\n");

  chif_net_socket target_sock;
  chif_net_protocol proto = CHIF_NET_PROTOCOL_TCP;
  chif_net_address_family fam = CHIF_NET_ADDRESS_FAMILY_IPV4;

  chif_net_result res = chif_net_open_socket(&target_sock, proto, fam);
  report_success_or_die(res, "open target socket");

  chif_net_address target_addr;
  res = chif_net_create_address(&target_addr, target_ip, target_port, fam);
  report_success_or_die(res, "constructed target address");

  res = chif_net_connect(target_sock, target_addr);
  report_success_or_die(res, "connecting to remote");

  bool bridge_open = true;
  enum buf_size { buf_size = 4096 };
  uint8_t buf[buf_size+1]; // +1 allows to null terminate the message for print
  ssize_t sent_bytes, read_bytes;

#define report_if_fail(msg) if (res != CHIF_NET_RESULT_SUCCESS)         \
  {bridge_open=false;printf("[bridge_connection] failed: %s\n", msg);break;}

  while (bridge_open) {
    bool can_do;
    res = chif_net_can_read(*sock, &can_do);
    report_if_fail("can_read sock");
    if (can_do) {
      res = chif_net_read(*sock, buf, buf_size, &read_bytes);
      report_if_fail("sock read");
      res = chif_net_write(target_sock, buf, read_bytes, &sent_bytes);
      report_if_fail("target_sock write");
    }

    res = chif_net_can_read(target_sock, &can_do);
    report_if_fail("can_read target_sock");
    if (can_do) {
      res = chif_net_read(target_sock, buf, buf_size, &read_bytes);
      report_if_fail("target_sock read");
      res = chif_net_write(*sock, buf, read_bytes, &sent_bytes);
      report_if_fail("sock write");
    }

    int ures = usleep((useconds_t)1000);
    if (ures != 0) {
      printf("usleep returned %d\n", ures);
      exit(1);
    }
  }

  chif_net_close_socket(sock);
  chif_net_close_socket(&target_sock);

  printf("~ bridge closed ~\n");
}

// ============================================================ //

int main()
{
  chif_net_startup(); // needed if on windows

  const char* target_ip = "192.168.234.130";
  const uint16_t target_port = 1337;
  printf("~ bridge ~\n\nWill bridge connections to %s:%d\n", target_ip, target_port);

  bool run = true;
  while (run) {
    chif_net_socket sock = wait_for_connection(target_port);
    bridge_connection(&sock, target_ip, target_port);
  }

  printf("shutting down");
  chif_net_shutdown(); // needed if on windwos

  return 0;
}
