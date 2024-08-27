
#ifndef INCLUDED_LibThreePartyEncrypt_H
#define INCLUDED_LibThreePartyEncrypt_H
#include <array>
#include <optional>
#include <cstdint>
#include <crypto/fipsmodule/modes/internal.h>
#include "ssl/EmpWrapperAG2PC.hpp"
#include "ssl/Messaging.hpp"
#include "ssl/TLSSocket.hpp"
#include "ssl/Util.hpp"

// Macros rarely help readability. Here, though, it makes life a lot easier.
#define RETURN_FALSE_IF_SSL_FAILED(ssl_size, target_size)                      \
  do {                                                                         \
    if (ssl_size <= 0 || static_cast<unsigned>(ssl_size) != target_size)       \
      return false;                                                            \
  } while (0)


namespace ThreePartyrEncrypt {
using aes_encrypt_function_type = SSL::aes_encrypt_function_type;
using aes_decrypt_function_type = SSL::aes_decrypt_function_type;

bool mult_H_power(std::array<uint8_t, 16> &in_out_block, uint8_t H_power[16]);
bool run_aes_joint_circuit(
    const EmpWrapperAG2PCConstants::AESCircuitJointIn &in,
    EmpWrapperAG2PCConstants::AESCircuitJointOut &out,
    EmpWrapperAG2PC *const circuit) noexcept;
bool aes_ctr(SSL *const ssl, std::array<uint8_t, 16> &key,
                                  std::array<uint8_t, 16> &iv,
                                  std::array<uint8_t, 16> &in,
                                  std::array<uint8_t, 16> &out) noexcept;
bool aes_encrypt_from_ssl(SSL *const ssl, uint8_t *out, uint8_t *out_suffix,
                          size_t out_suffix_len, uint8_t type,
                          uint16_t record_version, const uint8_t sequence[8],
                          bssl::Span<const uint8_t> header, const uint8_t *in,
                          size_t in_len);

bool aes_decrypt_from_ssl(SSL *const ssl, bssl::Span<uint8_t> *out,
                          uint8_t type, uint16_t version,
                          const uint8_t sequence[8],
                          bssl::Span<const uint8_t> header,
                          bssl::Span<uint8_t> in);

bool send_handshake_data(SSL *const, bssl::Span<uint8_t>);
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
inline size_t get_max_gcm_power(size_t length) {
  return ((length + 15) / 16 + 1) * 16;
}

template <bool is_encrypt>
bool send_aes_message(SSL *const verifier, const bssl::Span<const uint8_t> &ad,
                      const uint8_t sequence[8],
                      std::optional<const bssl::Span<const uint8_t>> in = std::nullopt)
                      noexcept {
  bssl::ScopedCBB cbb;
  bssl::Array<uint8_t> write_to;

  constexpr static auto header = is_encrypt
                                     ? Messaging::MessageHeaders::AES_ENC
                                     : Messaging::MessageHeaders::AES_DEC;

  constexpr size_t sequence_length = 8;
  size_t total_length =
      sizeof(header) + sizeof(uint64_t) + ad.size() + sequence_length;
  if (!is_encrypt) {
    total_length += in->size();
  }
  if (!write_to.Init(total_length)) {
    return false;
  }
  if (!CBB_init(cbb.get(), total_length) ||
      !CBB_add_u8(cbb.get(), static_cast<uint8_t>(header)) ||
      !CBB_add_u64(cbb.get(), ad.size()) ||
      !CBB_add_bytes(cbb.get(), ad.data(), ad.size()) ||
      !CBB_add_bytes(cbb.get(), sequence, sequence_length) ||
      !(is_encrypt || CBB_add_bytes(cbb.get(), in->data(), in->size())) ||
      !CBBFinishArray(cbb.get(), &write_to)) {
    return false;
  }
  const auto amount_written =
      SSL_write(verifier, write_to.data(), static_cast<int>(total_length));
  RETURN_FALSE_IF_SSL_FAILED(amount_written, total_length);

  return true;
}

// @param: is_make_or_verify
// True : we want to make a tag
// False: we want to verify the tag
template <bool is_make_or_verify>
bool run_gcm_tag_circuit(EmpWrapperAG2PC *const tag_circuit,
                         EmpWrapperAG2PC *const vfy_circuit,
                         EmpWrapperAG2PC *const aes_circuit,
                         const std::array<uint8_t, 16> &key,
                         const std::array<uint8_t, 16> &iv,
                         const std::array<uint8_t, 16> &tag_share,
                         const std::array<uint8_t, 16> &mask_or_servertag,
                         std::array<uint8_t, 16> &outtag) noexcept {
  using namespace EmpWrapperAG2PCConstants;
  if (!tag_circuit || !vfy_circuit || !aes_circuit)
    return false;
  std::conditional_t<is_make_or_verify, aes_gcm_tag_input_type,
                   aes_gcm_vfy_input_type>
      input;
  std::conditional_t<is_make_or_verify, aes_gcm_tag_output_type,
                   aes_gcm_vfy_output_type>
      output;
  size_t offset = 0;
  Util::swap_byte_order(key.begin(), input.begin(), key.size());
  offset += sizeof(key);
  Util::swap_byte_order(iv.begin(), input.begin() + offset, iv.size());
  offset += sizeof(iv);
  Util::swap_bitorder(tag_share.begin(), input.begin() + offset,
                      tag_share.size());
  offset += sizeof(tag_share);
  Util::swap_bitorder(mask_or_servertag.begin(), input.begin() + offset,
                      mask_or_servertag.size());
  offset += sizeof(mask_or_servertag);
  assert(offset ==
         (is_make_or_verify ? GCM_TAG_INPUT_SIZE : GCM_VFY_INPUT_SIZE));

  if constexpr (is_make_or_verify) {
    if(!tag_circuit->make_tag(input, output, vfy_circuit, aes_circuit) || output[0] == 0) {
        return false;
    }
    Util::swap_bitorder(output.begin() + 1, outtag.begin(), outtag.size());
  } else {
    if(!vfy_circuit->verify_tag(input, output, tag_circuit, aes_circuit)) {
      return false;
    }
    std::copy(output.begin(), output.end(), outtag.begin());
  }
  return true;
}
} // namespace ThreePartyrEncrypt

template <Messaging::MessageHeaders target_header>
bool is_correct_header(SSL *ssl) noexcept {
  // This function just reads a single header from `ssl` and checks that it is
  // the one that was expected. This can return false if reading fails too.
  static_assert(sizeof(target_header) == sizeof(uint8_t),
                "is_correct_header assumes sizeof(target_header) == 1");
  uint8_t header_buf;
  const auto amount_read = SSL_read(ssl, &header_buf, sizeof(header_buf));
  RETURN_FALSE_IF_SSL_FAILED(amount_read, sizeof(header_buf));

  // We now need to convert out of the serialisation format. This is likely a
  // big endian value, so we need to explicitly undo that conversion.
  CBS in_cbs;
  CBS_init(&in_cbs, &header_buf, sizeof(header_buf));

  uint8_t in_header;
  if (!CBS_get_u8(&in_cbs, &in_header) ||
      !Messaging::is_valid_header(in_header)) {
    return false;
  }

  return static_cast<Messaging::MessageHeaders>(in_header) == target_header;
}

bool write_single_header(TLSSocket &socket,
                                const Messaging::MessageHeaders header);
bool read_single_header(TLSSocket &socket,
                               Messaging::MessageHeaders &header);
bool read_single_u64(TLSSocket &socket, uint64_t &size) noexcept;
#endif