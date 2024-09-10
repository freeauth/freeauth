/*
  This file exists to allow one to easily benchmark how long the 3P-HS takes in
  an end-to-end setting. At a high-level, this file similarly to the tests in
  Server.t.cpp: we simply run the 3P-HS forward between two parties.
*/

#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <getopt.h>

#include "../FreeAuth/common.h"
#include <cstdint>
#include <iostream>
#include <netinet/in.h>
#include <openssl/bytestring.h>
#include <openssl/ssl.h>
#include <ostream>
#include <ssl/Messaging.hpp>
#include <ssl/TestUtil.hpp>
#include <string>
#include <sys/socket.h>

char receive_buf[BUFSIZE],
    RESPONSE_0[] = "220 smtp.qq.com Esmtp QQ QMail Server\n",
    RESPONSE_1[] =
        "250-smtp.qq.com Esmtp QQ QMail Server\n",
    RESPONSE_2[] = "334 VXNlcm5hbWU6\n",
    RESPONSE_3[] = "334 UGFzc3dvcmQ6\n",
    RESPONSE_4[] = "235 Authentication successful\n";
int length;

void clientProc(int connect_sock) {
  SSL_CTX *ctx = SSL_CTX_new(TLS_method());
  SSL_CTX_use_certificate_file(ctx, "../TestFreeAuth/TestCA/certs/server.crt",
                               SSL_FILETYPE_PEM);
  SSL_CTX_use_PrivateKey_file(ctx, "../TestFreeAuth/TestCA/keys/server.key",
                              SSL_FILETYPE_PEM);
  SSL *cur_ssl = SSL_new(ctx);
  SSL_set_fd(cur_ssl, connect_sock);
  if (SSL_accept(cur_ssl) < 1)
    onError("SSL_accept() wrong!");
  if (SSL_pending(cur_ssl) > 0)
    std::cout << "SSL_pending() return non-zero!" << std::endl; // For debug
  std::cout << "[Server] Finished handshake with client " << connect_sock << " "
            << (int)(cur_ssl->s3->read_traffic_secret_len) << std::endl;
  if (SSL_write(cur_ssl, RESPONSE_0, sizeof(RESPONSE_0)) <= 0 ||
      SSL_read(cur_ssl, receive_buf, BUFSIZE) <= 0 ||
      SSL_write(cur_ssl, RESPONSE_1, sizeof(RESPONSE_1)) <= 0 ||
      SSL_read(cur_ssl, receive_buf, BUFSIZE) <= 0 ||
      SSL_write(cur_ssl, RESPONSE_2, sizeof(RESPONSE_2)) <= 0 ||
      SSL_read(cur_ssl, receive_buf, BUFSIZE) <= 0 ||
      SSL_write(cur_ssl, RESPONSE_3, sizeof(RESPONSE_3)) <= 0 ||
      SSL_read(cur_ssl, receive_buf, BUFSIZE) <= 0 ||
      SSL_write(cur_ssl, RESPONSE_4, sizeof(RESPONSE_4)) <= 0) {
    std::cerr << "[Server] SSL function failed! " << std::endl;
  }
  SSL_shutdown(cur_ssl);
  std::cout << "[Server] client " << connect_sock << " has down." << std::endl;
}

static void server_run(int server) {
  int client;
  char ipstring[100];
  socklen_t len = sizeof(sockaddr_in);
  sockaddr_in client_addr;
  while (true) {
    client = accept(server, (sockaddr *)&client_addr, &len);
    inet_ntop(AF_INET, &client_addr.sin_addr, ipstring, len);
    std::cout << "[Server] New client connect in: " << ipstring << std::endl;
    // std::thread client_proc(clientProc,client);
    clientProc(client);
  }
}

int main(int argc, char *argv[]) {
  std::string ip = "127.0.0.1";

  uint16_t server_port = 18388;

  const char *const short_opts = "a:p:";
  const option long_opts[] = {{"ip", required_argument, nullptr, 'a'},
                              {"server port", required_argument, nullptr, 'p'}};

  for (;;) {
    const auto opt = getopt_long(argc, argv, short_opts, long_opts, nullptr);
    if (opt == -1) {
      break;
    }

    switch (opt) {
    case 'a':
      ip = std::string(optarg);
      break;
    case 'p':
      server_port = static_cast<uint16_t>(std::stoi(optarg));
      break;
    }
  }

  int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0)
    onError("main(): socket() call error.");
  sockaddr_in sa;
  memset(&sa, 0, sizeof(sockaddr_in));
  inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
  sa.sin_family = AF_INET;
  sa.sin_port = htons(server_port);
  if (bind(sock, (sockaddr *)&sa, sizeof(sockaddr_in)) < 0)
    onError("main(): can't bind address.");
  if (listen(sock, SOMAXCONN) < 0)
    onError("main(): can't listen() on such port.");
  std::cerr << "[Server] simple server listen on:" << ip << ":" << server_port
            << std::endl;

  std::cerr << "[Server] Alternatively, you can run the client program by "
               "pasting the following command into another terminal: \n"
            << "./TestSMTPProver -a " << ip << " -s " << server_port
            << " -v VERIFIER_PORT" << std::endl;
  server_run(sock);
}
