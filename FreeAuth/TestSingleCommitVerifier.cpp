#include <getopt.h>
#include "common.h"
#include "ssl/TLSSocket.hpp"
#include "ssl/TestUtil.hpp"

std::unique_ptr<EmpWrapperAG2PC> commit_circuit;
SSL *prover;
std::array<uint8_t, 12> client_iv;
std::array<uint8_t, 16> client_key_share;

bool commit() noexcept {
    commit_circuit.reset(EmpWrapperAG2PC::build_commit_circuit(
        prover, emp::ALICE, EmpWrapperAG2PCConstants::COMMIT_CIRCUIT_TAG));
    if (!commit_circuit) {
      return false;
    }
    commit_circuit->do_preproc();
    // For test, iv = zero
    std::array<uint8_t, 16> iv{};
    std::array<uint8_t, 32> outhash;
    std::array<uint8_t, 16*EmpWrapperAG2PCConstants::COMMIT_INPUT_BLOCK_NUM> outaes;

    // Calculate iv
    uint8_t sequence[8];
    static constexpr uint64_t email_block_seq = 2;
    // 0: EHLO / 1: AUTH LOGIN / 2: Base64(email_address)
    CRYPTO_store_u64_be(sequence, email_block_seq);
    OPENSSL_memcpy(iv.begin() + 4, sequence, 8);
    Util::xor_func(client_iv.begin(), iv.begin(), 12);
    iv[15] = 2;

    if (!ThreePartyrEncrypt::run_commit_circuit(
            commit_circuit.get(), client_key_share, iv, outaes,
            iv, outhash, outaes))
      return false;
    return true;
  }

int main(int argc, char *argv[]) {
  std::string ip = "127.0.0.1";

  uint16_t verifier_port = 18389;

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
      verifier_port = static_cast<uint16_t>(std::stoi(optarg));
      break;
    }
  }
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  SSL_CTX_use_certificate_file(ctx.get(), "../FreeAuth/TestCA/certs/verifier.crt",
                               SSL_FILETYPE_PEM);
  SSL_CTX_use_PrivateKey_file(ctx.get(), "../FreeAuth/TestCA/keys/verifier.key",
                              SSL_FILETYPE_PEM);

  auto pv_ctx = CreateContextWithTestCertificate(TLS_method());
  TLSSocket v(pv_ctx.get());
  v.set_ip_v4();
  v.set_port(verifier_port);
  v.set_addr(ip);
  v.bind();
  v.listen(1);
  if (!v.accept() || !v.do_handshake())
    std::abort();
  

  prover = v.get_ssl_object();
  
  Util::generate_random_bytes(client_iv);
  Util::generate_random_bytes(client_key_share);

  commit();
}