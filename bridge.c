#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <getopt.h>
#include <limits.h>

#define CHIF_NET_IMPLEMENTATION
#include "chif/chif_net.h"

#include "argparse/argparse.h"

// ============================================================ //
// prototypes
// ============================================================ //

void* init_bridge(void* bridge_ctx);
void serve_bridge(chif_net_socket con_sock, chif_net_socket target_sock);

// ============================================================ //
// structs
// ============================================================ //

typedef uint32_t tcp_user_timeout_type;

struct bridge_ctx {
  chif_net_socket cli_sock;
  const char* target_ip;
  uint16_t target_port;
  tcp_user_timeout_type tcp_user_timeout;
};

struct bridge_options {
  const char* target_ip;
  uint16_t target_port;
  uint16_t listen_port;
  tcp_user_timeout_type tcp_user_timeout;
};

// ============================================================ //
// functions
// ============================================================ //

/**
 * Use for critical parts of the code where it must result in
 * success, or exit the program.
 */
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

/**
 * Listen for connections and start serving them
 *
 * @param listen_port
 * @param target_ip Ip address of the bridge target.
 * @param target_port Port of the bridge target.
 */
void connection_server(struct bridge_options* opts)
{
  printf("\n~ connection_server ~\n");
  chif_net_socket sock;
  chif_net_protocol proto = CHIF_NET_PROTOCOL_TCP;
  chif_net_address_family fam = CHIF_NET_ADDRESS_FAMILY_IPV4;

  chif_net_result res = chif_net_open_socket(&sock, proto, fam);
  report_success_or_die(res, "[connection_server] open server socket");

  res = chif_net_set_reuse_addr(sock, true);
  report_success_or_die(res, "[connection_server] reuse addr");

  res = chif_net_bind(sock, opts->listen_port, fam);
  report_success_or_die(res, "[connection_server] bind server");

  res = chif_net_listen(sock, CHIF_NET_DEFAULT_MAXIMUM_BACKLOG);
  report_success_or_die(res, "[connection_server] listen");

  // TODO catch interrupts and set while to false
  while (true) {
    chif_net_address cli_addr;
    printf("[connection_server] waiting for client to connect\n");
    chif_net_socket cli_sock = chif_net_accept(sock, &cli_addr);

    if (cli_sock == CHIF_NET_INVALID_SOCKET) {
      printf("[connection_server] warning: failed to accept client\n");
    }
    else {
      pthread_t thread;
      struct bridge_ctx* bridge_ctx = malloc(sizeof(struct bridge_ctx));
      bridge_ctx->cli_sock = cli_sock;
      bridge_ctx->target_ip = opts->target_ip;
      bridge_ctx->target_port = opts->target_port;
      bridge_ctx->tcp_user_timeout = opts->tcp_user_timeout;
      int res = pthread_create(&thread, NULL, init_bridge, (void*)(bridge_ctx));
      if (res) {
        printf("[conenction_server] failed to creat thread\n");
      }

      pthread_detach(thread);
    }
  }

  res = chif_net_close_socket(&sock);
  report_success_or_die(res, "closed server socket");
}

/**
 * Setup the bridge connection, open new thread and connect to target
 */
void* init_bridge(void* void_bridge_ctx)
{
  struct bridge_ctx* bridge_ctx = (struct bridge_ctx*)void_bridge_ctx;
  chif_net_socket target_sock = -1;

  char cli_ip[CHIF_NET_IPVX_STRING_LENGTH];
  chif_net_result res1 = chif_net_get_peer_name(bridge_ctx->cli_sock, cli_ip, CHIF_NET_IPVX_STRING_LENGTH);
  uint16_t cli_port;
  chif_net_result res2 = chif_net_get_peer_port(bridge_ctx->cli_sock, &cli_port);
  if (res1 && res2) {
    printf("  [%d<->%d] [bridge_init] new client connected from %s:%d\n",
           bridge_ctx->cli_sock, target_sock, cli_ip, cli_port);
  }
 else {
   printf("  [%d<->%d] [bridge_init] new client connected from unknown\n", bridge_ctx->cli_sock, target_sock);
 }

#define report_success_or_return(res, msg) {                            \
    if (res == CHIF_NET_RESULT_SUCCESS)                                 \
      printf("  [%d<->%d] [bridge_init] %s\n", bridge_ctx->cli_sock, target_sock, msg); \
    else {                                                              \
      printf("  [%d<->%d] [bridge_init] FATAL %d: %s\n", bridge_ctx->cli_sock, target_sock, res, msg); \
      chif_net_close_socket(&(bridge_ctx->cli_sock));                   \
      chif_net_close_socket(&target_sock);                              \
      return (int*)1; }                                                 \
}

  chif_net_protocol proto = CHIF_NET_PROTOCOL_TCP;
  chif_net_address_family fam = CHIF_NET_ADDRESS_FAMILY_IPV4;

  chif_net_result res = chif_net_open_socket(&target_sock, proto, fam);
  report_success_or_return(res, "open target socket");

  chif_net_address target_addr;
  res = chif_net_create_address(&target_addr, bridge_ctx->target_ip, bridge_ctx->target_port, fam);
  report_success_or_return(res, "constructed target address");

  res = chif_net_connect(target_sock, target_addr);
  report_success_or_return(res, "connecting to remote");

  char target_ip[CHIF_NET_IPVX_STRING_LENGTH];
  chif_net_result tres1 = chif_net_get_peer_name(target_sock, target_ip, CHIF_NET_IPVX_STRING_LENGTH);
  uint16_t target_port;
  chif_net_result tres2 = chif_net_get_peer_port(target_sock, &target_port);
  if (tres1 && tres2) {
    printf("  [%d<->%d] [bridge_init] bridge connected to %s:%d\n",
           bridge_ctx->cli_sock, target_sock, target_ip, target_port);
  }
  else {
    printf("  [%d<->%d] [bridge_init] bridge connected to unknown\n", bridge_ctx->cli_sock, target_sock);
  }

  if (bridge_ctx->tcp_user_timeout) {
    res = chif_net_tcp_set_user_timeout(bridge_ctx->cli_sock, bridge_ctx->tcp_user_timeout);
    report_success_or_return(res, "setting user timeout on cli sock");

    res = chif_net_tcp_set_user_timeout(target_sock, bridge_ctx->tcp_user_timeout);
    report_success_or_return(res, "setting user timeout on target sock");
  }

  serve_bridge(bridge_ctx->cli_sock, target_sock);

  return 0;
}

/**
 * serve a client
 *
 *
 */
void serve_bridge(chif_net_socket con_sock, chif_net_socket target_sock)
{
  printf("  [%d<->%d] ~ serve bridge active ~\n", con_sock, target_sock);

  bool bridge_open = true;
  enum buf_size { buf_size = 4096 };
  uint8_t buf[buf_size+1]; // +1 allows to null terminate the message for print
  ssize_t sent_bytes, read_bytes;

#define report_if_fail(msg) if (res != CHIF_NET_RESULT_SUCCESS)         \
  {bridge_open=false;printf("  [%d<->%d] [serve_bridge] failed: %s\n", con_sock, target_sock, msg);break;}

  while (bridge_open) {
    bool should_sleep = true;
    bool can_do;
    int res = chif_net_can_read(con_sock, &can_do);
    report_if_fail("can_read sock");
    if (can_do) {
      should_sleep = false;
      res = chif_net_read(con_sock, buf, buf_size, &read_bytes);
      report_if_fail("sock read");
      res = chif_net_write(target_sock, buf, read_bytes, &sent_bytes);
      report_if_fail("target_sock write");
    }

    res = chif_net_can_read(target_sock, &can_do);
    report_if_fail("can_read target_sock");
    if (can_do) {
      should_sleep = false;
      res = chif_net_read(target_sock, buf, buf_size, &read_bytes);
      report_if_fail("target_sock read");
      res = chif_net_write(con_sock, buf, read_bytes, &sent_bytes);
      report_if_fail("sock write");
    }

    if (should_sleep) { // only sleep if we did nothing
      struct timespec sleeptime = {.tv_sec = 0, .tv_nsec = 10000000};
      int ures = nanosleep(&sleeptime, NULL);
      if (ures != 0) {
        printf("  [%d<->%d] [serve_bridge] nanosleep returned %d\n", con_sock, target_sock, ures);
      }
    }
  }

  printf("  [%d<->%d] ~ bridge closed ~\n", con_sock, target_sock);

  chif_net_close_socket(&con_sock);
  chif_net_close_socket(&target_sock);
}

void display_help()
{
  fprintf(stderr, "usage: ...\n");
}

// ============================================================ //
// main
// ============================================================ //

static const char *const usage[] = {
  "test_argparse [options] [[--] args]",
  "test_argparse [options]",
  NULL,
};

int main(int argc, const char** argv)
{
  char* target_ip = NULL;
  uint32_t target_port = 0;
  uint32_t listen_port = 0;
  uint32_t timeout = 0;

  struct argparse_option options[] = {
    OPT_HELP(),
    OPT_GROUP("Bridge Target Options"),
    OPT_STRING('i', "ip", &target_ip, "Bridge target ip", NULL, 0, 0),
    OPT_INTEGER('p', "port", &target_port, "Bridge target port", NULL, 0, 0),
    OPT_GROUP("Server Options"),
    OPT_INTEGER('l', "listen", &listen_port, "Listen port", NULL, 0, 0),
    OPT_GROUP("General Options"),
    OPT_INTEGER('t', "tcp-user-timeout", &timeout, "Linux only feature. tcp user timeout", NULL, 0, 0),
    OPT_END(),
  };

  struct argparse argparse;
  argparse_init(&argparse, options, usage, 0);
  argparse_describe(&argparse, "\nTODO: write description", "\nTODO: Write additional info here");
  argc = argparse_parse(&argparse, argc, argv);

  if (target_port > USHRT_MAX) {
    fprintf(stderr, "attempted to set --port=%d, but maximum port value is %d\n",
            target_port, USHRT_MAX);
    exit(1);
  }

  if (listen_port > USHRT_MAX) {
    fprintf(stderr, "attempted to set --listen=%d, but maximum port value is %d\n",
            listen_port, USHRT_MAX);
    exit(1);
  }

  chif_net_startup(); // needed if on windows

  const uint16_t dlisten_port = 1337;
  const char* dtarget_ip = "192.168.208.128";
  const uint16_t dtarget_port = 1337;
  printf("~ bridge ~\n\n~ options ~\n");

  printf("bridging to %s:%d\n", target_ip != NULL ? target_ip : dtarget_ip,
         target_port != 0 ? target_port : dtarget_port);
  printf("listening on port %d\n", listen_port != 0 ? listen_port : dlisten_port);
  if (timeout != 0) printf("tcp_user_timeout: %d\n", timeout);

  struct bridge_options bridge_opt = {
    .target_ip = target_ip != NULL ? target_ip : dtarget_ip,
    .target_port = target_port != 0 ? target_port : dtarget_port,
    .listen_port = listen_port != 0 ? listen_port : dlisten_port,
    .tcp_user_timeout = timeout
  };

  connection_server(&bridge_opt);

  printf("~ shutting down ~\n");
  chif_net_shutdown(); // needed if on windwos

    return 0;
}
