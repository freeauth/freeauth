#include "ssl/EmpWrapperAG2PC.hpp"
#include "ssl/Messaging.hpp"
#include <string.h>
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/tls1.h>

#define BUFSIZE 1024

class TLSSocket;
std::pair<size_t, size_t> get_bandwith_from_single_ssl(SSL *ssl) noexcept;
std::pair<size_t, size_t> get_bandwith_from_ssl(TLSSocket &sock) noexcept;
bool read_single_header(TLSSocket &socket,
                               Messaging::MessageHeaders &header);
namespace ThreePartyrEncrypt {
    void preproc_all_aes_gcm_circuits(SSL *ssl, bool single = false) noexcept;
    bool commit_email_address(SSL *ssl,
                          std::array<uint8_t, 16*EmpWrapperAG2PCConstants::COMMIT_INPUT_BLOCK_NUM> &email_address,
                          std::array<uint8_t, 16> &random_val) noexcept;
    bool run_commit_circuit(
        EmpWrapperAG2PC *const circuit, const std::array<uint8_t, 16> &key,
    const std::array<uint8_t, 16> &iv,
    const std::array<uint8_t, 16*EmpWrapperAG2PCConstants::COMMIT_INPUT_BLOCK_NUM> &email_data,
    const std::array<uint8_t, 16> &random_val,
    std::array<uint8_t, 32> &sha256_value,
    std::array<uint8_t, 16*EmpWrapperAG2PCConstants::COMMIT_INPUT_BLOCK_NUM> &crypted_out) noexcept;
}

// only for test
void onError(const char *message) {
  // std::cerr << "[Error] " << message <<" "<< strerror(errno) << std::endl
  //           << "The program will exit now!" << std::endl;
  exit(1);
}
