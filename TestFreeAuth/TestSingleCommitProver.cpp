#include <getopt.h>
#include "../FreeAuth/common.h"
#include "ssl/TLSSocket.hpp"
#include "ssl/TestUtil.hpp"

int main(int argc, char *argv[]) {
    std::string ip = "127.0.0.1";

  uint16_t  verifier_port=18389,length=0;
  bool single = false;
  std::unique_ptr<char> buf;

  const char *const short_opts = "a:v:l:t";
  const option long_opts[] = {
      {"ip", required_argument, nullptr, 'a'},
      {"verifier port", required_argument, nullptr, 'v'},
      {"test data length", required_argument, nullptr, 'l'},
      {"single", no_argument, nullptr, 't'}
      };

  for (;;) {
    const auto opt = getopt_long(argc, argv, short_opts, long_opts, nullptr);
    if (opt == -1) {
      break;
    }

    switch (opt) {
    case 'a':
      ip = std::string(optarg);
      break;
    case 'v':
      verifier_port = static_cast<uint16_t>(std::stoi(optarg));
      break;
    case 'l':
      length = static_cast<uint16_t>(std::stoi(optarg));
      buf.reset(new char[length]);
      break;
    case 't':
      single = true;
      break;
    }
  }

  auto pv_ctx = CreateContextWithTestCertificate(TLS_method());
  TLSSocket v(pv_ctx.get(), false);
  v.set_ip_v4();
  if(!v.connect_to(ip, verifier_port)) std::abort();
  SSL *ssl = v.get_ssl_object();
  ssl->verifier = ssl;
  std::array<uint8_t, 16*EmpWrapperAG2PCConstants::COMMIT_INPUT_BLOCK_NUM> email_address;
  std::array<uint8_t, 16> random_val;
  Util::generate_random_bytes(email_address);
  Util::generate_random_bytes(random_val);
  Util::generate_random_bytes(ssl->client_iv);
  Util::generate_random_bytes(ssl->client_key_share);

  auto begin_conmmit = std::chrono::steady_clock::now();
  ThreePartyrEncrypt::commit_email_address(ssl, email_address, random_val);
  auto end_commit = std::chrono::steady_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::duration<double>>(
      end_commit - begin_conmmit);
  printf("Commit time costs: %.6f\n",duration.count());
}