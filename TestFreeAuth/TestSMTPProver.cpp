/*
  This file exists to allow one to easily benchmark how long the 3P-HS takes in
  an end-to-end setting. At a high-level, this file similarly to the tests in
  Server.t.cpp: we simply run the 3P-HS forward between two parties.
*/

#include <getopt.h>

#include "../FreeAuth/common.h"
#include "nodes/Server.hpp"
#include "ssl/TLSSocket.hpp"
#include "ssl/TestUtil.hpp"
#include <iostream>
#include <ssl/Messaging.hpp>
#include <string>

char buf[BUFSIZE];
const char HELO_MESSAGE[] = "HELO emailreg\r\n",
           TEST_AUTH_PLAIN_CONTENT[] =
               "AUTH PLAIN AHVzZXJuYW1lQHFxLmNvbQB5b3VyX3Bhc3N3b3Jk\r\n",
            AUTH_LOGIN_COMMAND[] = "AUTH LOGIN\r\n",
            AUTH_LOGIN_USERNAME[] = "dXNlcm5hbWVAcXEuY29t\r\n",
            AUTH_LOGIN_PASS[] = "eW91cl9wYXNzd29yZA==\r\n",
           TLS_WRITE_ERROR[] = "TLSSocket write error!",
           END_SESSION[] = "\x1a",
           TLS_READ_ERROR[] = "TLSSocket read error!";


inline void socketRecvAndLog(TLSSocket &sock) {
  return;
  int len;
  if ((len = sock.read(buf, BUFSIZE)) < 0)
    onError(TLS_READ_ERROR);
  for (int i = 0, flag = 1; i < len; i++) {
    if (buf[i] == '\r' || buf[i] == 0) {
      break;
    } else if (flag) {
      flag = 0;
      std::cout << "Recv <- ";
    }
    putchar(buf[i]);
  }
}

inline void socketSendAndLog(TLSSocket &sock, const void *buffer,
                             const size_t leng) {
  if (!sock.write(buffer, leng))
    onError(TLS_WRITE_ERROR);
  std::cout << "Send -> " << (const char *)buffer;
}

inline void sendAndRecv(TLSSocket &sock, const void *buffer,
                        const size_t leng) {
  socketSendAndLog(sock, buffer, leng);
  socketRecvAndLog(sock);
}

void SMTP_PlainCoreProc(TLSSocket &sock) {
  socketRecvAndLog(sock);
  sendAndRecv(sock, HELO_MESSAGE, sizeof(HELO_MESSAGE) - 1);
  sendAndRecv(sock, AUTH_LOGIN_COMMAND, sizeof(AUTH_LOGIN_COMMAND) - 1);
  sendAndRecv(sock, AUTH_LOGIN_USERNAME, sizeof(AUTH_LOGIN_USERNAME) - 1);
  sendAndRecv(sock, AUTH_LOGIN_PASS, sizeof(AUTH_LOGIN_PASS) - 1);
}

int main(int argc, char *argv[]) {
  std::string server_ip = "127.0.0.1";
  std::string verifier_ip = "127.0.0.1";

  uint16_t server_port = 18388, verifier_port = 18389;
  bool single = false;

  const char *const short_opts = "a:e:s:v:t";
  const option long_opts[] = {
      {"server ip", required_argument, nullptr, 'a'},
      {"verifier ip", required_argument, nullptr, 'e'},
      {"server port", required_argument, nullptr, 's'},
      {"verifier port", required_argument, nullptr, 'v'},
      {"single", no_argument, nullptr, 't'}};

  for (;;) {
    const auto opt = getopt_long(argc, argv, short_opts, long_opts, nullptr);
    if (opt == -1) {
      break;
    }

    switch (opt) {
    case 'a':
      server_ip = std::string(optarg);
      break;
    case 'e':
      verifier_ip = std::string(optarg);
      break;
    case 's':
      server_port = static_cast<uint16_t>(std::stoi(optarg));
      break;
    case 'v':
      verifier_port = static_cast<uint16_t>(std::stoi(optarg));
      break;
    case 't':
      single = true;
      break;
    }
  }
  struct Prover {
    TLSSocket connection_to_verifier;
    TLSSocket connection_to_server;
  };

  auto pv_ctx = CreateContextWithTestCertificate(TLS_method());
  auto ps_ctx = CreateContextWithTestCertificate(TLS_method());

  Prover prover{TLSSocket(pv_ctx.get(), false), TLSSocket(ps_ctx.get(), false)};
  prover.connection_to_server.set_ip_v4();

  /////////////// Stage 1 ///////////////
  auto begin_connect_to_verifier = std::chrono::steady_clock::now();
  if (!prover.connection_to_verifier.connect_to_verifier_and_set_ssl_callback(
          prover.connection_to_server, verifier_ip, verifier_port, single)) {
    exit(1);
  };
  auto bandwidth_phase_0 = get_bandwith_from_ssl(prover.connection_to_server);

  /////////////// Stage 2 ///////////////
  // Just run the connection.
  auto begin_connect_to_server = std::chrono::steady_clock::now();
  if (!prover.connection_to_server.connect_to(server_ip, server_port))
    onError("[Prover] Error on connecting to server.");
  auto begin_preproc_all_aes_gcm_circuits = std::chrono::steady_clock::now();
  auto bandwidth_phase_1 = get_bandwith_from_ssl(prover.connection_to_server);
  puts("[Prover] Finished three party handshake");

  /////////////// Stage 3 ///////////////
  ThreePartyrEncrypt::preproc_all_aes_gcm_circuits(
      prover.connection_to_server.get_ssl_object(), single);
  auto bandwidth_phase_2 = get_bandwith_from_ssl(prover.connection_to_server);
  std::cout
      << "[Prover] Server connected. Now we begin send SMTP data packets\n";
  Util::print_hex_data(
      prover.connection_to_server.get_ssl_object()->client_key_share,
      "client_key_share");
  Util::print_hex_data(
      prover.connection_to_server.get_ssl_object()->server_key_share,
      "server_key_share");
  Util::print_hex_data(prover.connection_to_server.get_ssl_object()->client_iv,
                       "client_iv");
  Util::print_hex_data(prover.connection_to_server.get_ssl_object()->server_iv,
                       "server_iv");

  /////////////// Stage 4 ///////////////
  auto begin_aes_gcm = std::chrono::steady_clock::now();
  SMTP_PlainCoreProc(prover.connection_to_server);
  auto end_aes_gcm_dec = std::chrono::steady_clock::now();
  auto bandwidth_phase_3 = get_bandwith_from_ssl(prover.connection_to_server);

  /////////////// Stage End ///////////////
  printf("==============Time data print==============\n");
  auto duration = std::chrono::duration_cast<std::chrono::duration<double>>(
      begin_connect_to_server - begin_connect_to_verifier);
  printf("Preproc all handshake circuits before connect to server time costs: "
         "%.6f\n",
         //  "read: %lu B write: %lu B\n",
         duration.count());
        //  ,bandwidth_phase_0.first, bandwidth_phase_0.second);
  duration = std::chrono::duration_cast<std::chrono::duration<double>>(
      begin_preproc_all_aes_gcm_circuits - begin_connect_to_server);
  printf("Three party handshake total time costs: %.6f\n",
         //  " read: %lu B write: %lu B\n",
         duration.count());
        //  , bandwidth_phase_1.first - bandwidth_phase_0.first,
      // bandwidth_phase_1.second - bandwidth_phase_0.second);
  duration = std::chrono::duration_cast<std::chrono::duration<double>>(
      begin_aes_gcm - begin_preproc_all_aes_gcm_circuits);
  printf("Preproc AES-GCM-128 circuits time costs: %.6f\n",
         //  " read: %lu B write: %lu B\n",
         duration.count());
        //  ,bandwidth_phase_2.first - bandwidth_phase_1.first,
      // bandwidth_phase_2.second - bandwidth_phase_1.second);
  duration = std::chrono::duration_cast<std::chrono::duration<double>>(
      end_aes_gcm_dec - begin_aes_gcm);
  printf("Run threeparty SMTP auth proccess time costs: %.6f\n",
         //  " read: %lu B write: %lu B\n",
         duration.count());
        //  bandwidth_phase_3.first - bandwidth_phase_2.first,
        //  bandwidth_phase_3.second - bandwidth_phase_2.second);

    duration = std::chrono::duration_cast<std::chrono::duration<double>>(
      end_aes_gcm_dec - begin_connect_to_verifier);
  printf("Total time costs: %.6f\n",duration.count());
  // SSL_shutdown(prover.connection_to_server.get_ssl_object());
  // std::array<uint8_t, 16> random_val, email_data;
  // Util::generate_random_bytes<16>(random_val.begin());
  // Util::print_hex_data(random_val, "Commit Random");
  // OPENSSL_memcpy(email_data.begin(), AUTH_LOGIN_USERNAME, email_data.size());
  // Util::print_hex_data(email_data, "Commit email data");

  // ThreePartyrEncrypt::commit_email_address(prover.connection_to_server.get_ssl_object(), email_data, random_val);
  prover.connection_to_verifier.write(END_SESSION, 1);
  prover.connection_to_server.close();
  prover.connection_to_verifier.close();
  return 0;
}
