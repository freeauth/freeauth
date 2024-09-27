#include "LibThreePartyEncrypt.h"
#include "nodes/Server.hpp"
#include <err.h>

std::atomic<int> current_state, need_decrypt;
#define STATE_ERROR 8
#define STATE_CONNECTED_VERIFIER 1

bool ThreePartyrEncrypt::mult_H_power(std::array<uint8_t, 16> &in_out_block,
                                      uint8_t H_power[16]) {
  GCM128_KEY H_power_X;
  static int out_is_avx = 0;
  // init the Htable
  CRYPTO_ghash_init(&H_power_X.gmult, &H_power_X.ghash, &H_power_X.H,
                    H_power_X.Htable, &out_is_avx, H_power);
  // do the mult
  H_power_X.gmult(reinterpret_cast<uint64_t *>(in_out_block.begin()),
                  H_power_X.Htable);
  return true;
}

inline void iv_incr(std::array<uint8_t, 16> &iv) noexcept {
  uint8_t *location = iv.begin() + 12;
  uint32_t ctr = CRYPTO_load_u32_be(location) + 1;
  CRYPTO_store_u32_be(location, ctr);
}

inline void iv_reset(std::array<uint8_t, 16> &iv, uint32_t value = 1) noexcept {
  uint8_t *location = iv.begin() + 12;
  CRYPTO_store_u32_be(location, value);
}

inline auto get_last_block_info(size_t length, std::array<uint8_t, 16> &iv) {
  auto block_num = (length + 15) / 16;
  auto last_block_start = block_num * 16 - 16;
  iv_reset(iv, block_num + 1);
  return last_block_start;
}

// Circuit running process
bool ThreePartyrEncrypt::run_aes_joint_circuit(
    const EmpWrapperAG2PCConstants::AESCircuitJointIn &in,
    EmpWrapperAG2PCConstants::AESCircuitJointOut &out,
    EmpWrapperAG2PC *const circuit) noexcept {

  if (!circuit) {
    return false;
  }

  EmpWrapperAG2PCConstants::aes_joint_input_type input;

  EmpWrapperAG2PCConstants::aes_joint_output_type output;
  size_t offset = 0;

  // both party feed in their share of keyshare
  // combine input,input=pt+key+iv=48
  Util::swap_bitorder(in.pt_or_unused.begin(), input.begin(),
                      in.pt_or_unused.size());
  offset += sizeof(in.pt_or_unused);
  Util::swap_byte_order(in.key.begin(), input.begin() + offset, in.key.size());
  offset += sizeof(in.key);
  Util::swap_byte_order(in.iv.begin(), input.begin() + offset, in.iv.size());
  offset += sizeof(in.iv);
  assert(offset == EmpWrapperAG2PCConstants::AES_GCM_INPUT_SIZE);

  // do circuit
  offset = 0;
  if (!circuit->do_joint_aes(input, output)) {
    return false;
  }
  std::copy(output.cbegin(), output.cbegin() + 1, &out.cheated);
  offset += 1;
  Util::swap_bitorder(output.begin() + offset, out.pt.begin(), out.pt.size());
  offset += unsigned(out.pt.size());

  assert(offset == EmpWrapperAG2PCConstants::AES_GCM_OUTPUT_SIZE);

  return true;
}

bool ThreePartyrEncrypt::run_commit_circuit(
    EmpWrapperAG2PC *const circuit, const std::array<uint8_t, 16> &key,
    const std::array<uint8_t, 16> &iv,
    const std::array<uint8_t, 16*EmpWrapperAG2PCConstants::COMMIT_INPUT_BLOCK_NUM> &email_data,
    const std::array<uint8_t, 16> &random_val,
    std::array<uint8_t, 32> &sha256_value,
    std::array<uint8_t, 16*EmpWrapperAG2PCConstants::COMMIT_INPUT_BLOCK_NUM> &crypted_out) noexcept {

  if (!circuit) {
    return false;
  }

  EmpWrapperAG2PCConstants::commit_input_type input;
  EmpWrapperAG2PCConstants::commit_output_type output;

  size_t offset = 0;

  // both party feed in their share of keyshare
  // combine input,input=iv+key+pt+random=64
  Util::swap_byte_order(iv.begin(), input.begin(), iv.size());
  offset += sizeof(iv);

  Util::swap_byte_order(key.begin(), input.begin() + offset, key.size());
  offset += sizeof(key);

  OPENSSL_memcpy(input.begin() + offset, email_data.begin(),
                      email_data.size());
  offset += sizeof(email_data);

  OPENSSL_memcpy(input.begin() + offset, random_val.begin(), random_val.size());
  offset += sizeof(random_val);


  assert(offset == EmpWrapperAG2PCConstants::COMMIT_INPUT_SIZE);

  // do circuit
  offset = 0;
  if (!circuit->commit_data(input, output)) {
    return false;
  }
  uint8_t cheated;
  OPENSSL_memcpy(&cheated, output.cbegin(), sizeof(cheated));
  offset += sizeof(cheated);

  OPENSSL_memcpy(sha256_value.begin(), output.cbegin() + offset , sha256_value.size());
  offset += sizeof(sha256_value);

  Util::swap_bitorder(output.begin() + offset, crypted_out.begin(), crypted_out.size());
  offset += sizeof(crypted_out);

  assert(offset == EmpWrapperAG2PCConstants::COMMIT_OUTPUT_SIZE);
  if (cheated != 0xFF) {
    return false;
  }

  return true;
}

// add_new
bool ThreePartyrEncrypt::aes_ctr(SSL *const ssl, std::array<uint8_t, 16> &key,
                                 std::array<uint8_t, 16> &iv,
                                 std::array<uint8_t, 16> &in,
                                 std::array<uint8_t, 16> &out) noexcept {
  // build input
  EmpWrapperAG2PCConstants::AESCircuitJointIn input;
  input.key = key;
  input.iv = iv;
  input.pt_or_unused = in;

  EmpWrapperAG2PCConstants::AESCircuitJointOut output;

  if (!run_aes_joint_circuit(input, output, ssl->aes_joint_circuit)) {
    return false;
  }
  // Alice.iv==Bob.iv or return false
  if (!output.cheated) {
    return false;
  }

  std::copy(output.pt.cbegin(), output.pt.cend(), out.begin());
  return true;
}

bool ThreePartyrEncrypt::send_handshake_data(SSL *const ssl,
                                             bssl::Span<uint8_t> in) {
  if (!ssl || !ssl->verifier) {
    return false;
  }

  SSL *verifier = ssl->verifier;
  // The first 16 bytes will be the bytes for the CHTS, and the next 16 will be
  // for the SHTS.
  auto &ir_chts = ssl->chts_share;
  auto &ir_shts = ssl->shts_share;

  // Just forward the handshake data to the other party. We also send over a
  // hash of our key share: we prove commitments to this later on during
  // attestation.
  bssl::Array<uint8_t> tmp_buffer;
  auto size = sizeof(Messaging::MessageHeaders) + sizeof(uint64_t) + in.size() +
              sizeof(ir_chts) + sizeof(ir_shts);

  if (!tmp_buffer.Init(size)) {
    return false;
  }

  bssl::ScopedCBB cbb;
  if (!CBB_init(cbb.get(), size) ||
      !CBB_add_u8(cbb.get(),
                  static_cast<uint8_t>(
                      Messaging::MessageHeaders::ENC_HANDSHAKE_SEND)) ||
      !CBB_add_u64(cbb.get(), size - 1) ||
      !CBB_add_bytes(cbb.get(), in.data(), in.size()) ||
      !CBB_add_bytes(cbb.get(),
                     reinterpret_cast<const uint8_t *>(ir_chts.data()),
                     sizeof(ir_chts)) ||
      !CBB_add_bytes(cbb.get(),
                     reinterpret_cast<const uint8_t *>(ir_shts.data()),
                     sizeof(ir_shts)) ||
      !CBBFinishArray(cbb.get(), &tmp_buffer)) {
    return false;
  }

  const auto amount_written = SSL_write(verifier, tmp_buffer.data(),
                                        static_cast<int>(tmp_buffer.size()));
  RETURN_FALSE_IF_SSL_FAILED(amount_written, tmp_buffer.size());

  is_correct_header<Messaging::MessageHeaders::ENC_HANDSHAKE_RECV>(verifier);
  return true;
}

bool ThreePartyrEncrypt::aes_encrypt_from_ssl(
    SSL *const ssl, uint8_t *out, uint8_t *out_suffix, size_t out_suffix_len,
    uint8_t type, uint16_t record_version, const uint8_t sequence[8],
    bssl::Span<const uint8_t> header, const uint8_t *in, size_t in_len) {
  printf("[Prover] Call 2PC aes_encrypt with %lu bytes, seq = %d\n", in_len,
         sequence[7]);
  //=====> 1. Get ad and contact with verifier <=====
  uint8_t ad_storage[13];
  size_t i, j, round_len;
  bool is_tls_1_3 =
      ssl->s3->aead_write_ctx->ProtocolVersion() >= TLS1_3_VERSION;
  bssl::Span<const uint8_t> ad = ssl->s3->aead_write_ctx->GetAdditionalData(
      ad_storage, type, record_version, sequence, in_len, header);
  if (!send_aes_message<true>(ssl->verifier, ad, sequence)) {
    printf("Error! send_aes_message");
    return false;
  }
  //=====> 2. Set IV <=====
  std::array<uint8_t, 16> block{}, iv{}, out_block;
  std::copy(sequence, sequence + 8, iv.begin() + 4);
  if (is_tls_1_3) {
    Util::xor_func(ssl->client_iv.begin(), iv.begin(), 12);
  } else {
    // TODO For TLS 1.2
  }
  iv[15] = 2;
  //=====> 3. Now call aes_ctr to run 2PC circuit and encrypt <=====
  for (i = 0; i < in_len; i += 16) {
    for (j = 0; j < 16; j++)
      block[j] = i + j < in_len ? in[i + j] : 0;
    round_len = i + 16 > in_len ? in_len % 16 : 16;
    if (is_tls_1_3 && round_len < 16) {
      block[in_len % 16] = type;
      round_len++;
    }
    if (!aes_ctr(ssl, ssl->client_key_share, iv, block, out_block))
      return false;
    Util::print_hex_data(out_block, "aes_block");
    iv_incr(iv);
    for (j = 0; j < round_len; j++)
      out[i + j] = out_block[j];
  }
  if (is_tls_1_3 && in_len % 16 == 0) {
    block.fill(0);
    block[0] = type;
    aes_ctr(ssl, ssl->client_key_share, iv, block, out_block);
    Util::print_hex_data(out_block, "aes_block");
    out[in_len] = out_block[0];
  }
  //=====> 4. Move forward the out_suffix to consume the extra-in byte ======
  //======    and judge the tag length                                 <=====
  if (is_tls_1_3) {
    out_suffix++;
    out_suffix_len--;
    in_len++;
  }
  if (out_suffix_len != 16) {
    fprintf(stderr, "out_suffix_len: %lu != 16, abort!\n", out_suffix_len);
    std::abort();
  }
  //=====> 5. Prepare for calculating GCM tag <=====
  size_t gcm_power = get_max_gcm_power(in_len);
  auto muilt_and_xor_to_out = [&]() {
    ThreePartyrEncrypt::mult_H_power(block,
                                     ssl->cgcm_share.begin() + gcm_power);
    Util::xor_func(block.begin(), out_block.begin(), out_block.size());
    gcm_power -= 16;

  };
  //=====>  6. Now calculate GCM tag share <=====
  block.fill(0);
  out_block.fill(0);
  std::copy(ad.cbegin(), ad.cend(), block.begin());
  for (i = 0; i < in_len; i += 16) {
    muilt_and_xor_to_out();
    round_len = min(i + 16, in_len);
    std::copy(out + i, out + round_len, block.begin());
  }
  if (in_len % 16 != 0)
    std::fill(block.begin() + in_len % 16, block.end(), 0);
  muilt_and_xor_to_out();
  CRYPTO_store_u64_be(block.begin(), ad.size() * 8);
  CRYPTO_store_u64_be(block.begin() + 8, in_len * 8);
  muilt_and_xor_to_out();
  //=====> 7. Run make GCM Tag circuit and judge the result <=====
  iv_reset(iv);
  Util::print_hex_data(iv, "EK0 IV");
  Util::print_hex_data(block, "mask");
  Util::print_hex_data(out_block, "Tagshare");
  Util::generate_random_bytes(block);
  run_gcm_tag_circuit<true>(ssl->make_tag_circuit, ssl->verify_tag_circuit,
                            ssl->aes_joint_circuit, ssl->client_key_share, iv,
                            out_block, block, out_block);
  Util::xor_func(out_block.begin(), block.begin(), block.size());
  std::copy(block.begin(), block.end(), out_suffix);
  printf("[Prover] Run 2PC aes_encrypt successful, now send the packet to "
         "Server\n");
  return true;
}

bool ThreePartyrEncrypt::aes_decrypt_from_ssl(SSL *const ssl,
                                              bssl::Span<uint8_t> *out,
                                              uint8_t type, uint16_t version,
                                              const uint8_t sequence[8],
                                              bssl::Span<const uint8_t> header,
                                              bssl::Span<uint8_t> in) {
  if (need_decrypt == 0) {
    std::fill(in.begin(), in.end(), 0);
    in[in.size() - 17] = 0x17;
    *out = in.subspan(0, in.size() - 16);
    return true;
  }
  // TODO：The best way is that prover store the cyphertext into a buffer, when
  // the whole progress is ended, prover can send the buffer to the verifier with
  // the server_key_share. Then verifier could decrypt and verify the SMTP server auth
  // result alone without 2PC
  printf("[Prover] Call 2PC aes_decrypt with %lu bytes\n", in.size());
  //=====> 1. Get ad and contact with verifier <=====
  bool is_tls_1_3 =
      ssl->s3->aead_write_ctx->ProtocolVersion() >= TLS1_3_VERSION;
  size_t plaintext_len = 0, last_block_start;
  if (is_tls_1_3) {
    plaintext_len = in.size();
  } else {
    // TODO: TLS1.2
  }
  uint8_t ad_storage[13];
  bssl::Span<const uint8_t> ad = ssl->s3->aead_read_ctx->GetAdditionalData(
      ad_storage, type, version, sequence, plaintext_len, header);

  std::array<uint8_t, 16> block{}, iv{}, gcm_block{}, masked_out_block;
  if (!send_aes_message<false>(ssl->verifier, ad, sequence, in)) {
    printf("Error! send_aes_message");
    return false;
  }
  //=====> 2. Basic judge <=====
  constexpr size_t tag_len = 16;
  if (plaintext_len < tag_len) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_PACKET_LENGTH);
    return false;
  };
  plaintext_len = plaintext_len - tag_len;
  //=====> 3. Prepare for calculating GCM tag <=====
  size_t gcm_power = get_max_gcm_power(plaintext_len);
  auto muilt_and_xor_to_out = [&]() {
    ThreePartyrEncrypt::mult_H_power(block,
                                     ssl->sgcm_share.begin() + gcm_power);
    Util::xor_func(block.begin(), gcm_block.begin(), tag_len);
    gcm_power -= 16;

  };
  //=====>  4. Now calculate GCM tag share <=====
  std::copy(ad.cbegin(), ad.cend(), block.begin());
  muilt_and_xor_to_out();
  for (size_t i = 0; i < plaintext_len; i += 16) {
    for (size_t j = 0; j < 16; j++) {
      block[j] = i + j < plaintext_len ? in[i + j] : 0;
    }
    muilt_and_xor_to_out();
  }
  CRYPTO_store_u64_be(block.begin(), ad.size() * 8);
  CRYPTO_store_u64_be(block.begin() + 8, plaintext_len * 8);
  muilt_and_xor_to_out();
  //=====> 5. Set IV <=====
  if (is_tls_1_3) {
    std::copy(sequence, sequence + 8, iv.begin() + 4);
    Util::xor_func(ssl->server_iv.begin(), iv.begin(), 12);
  } else {
    // TODO For TLS 1.2
  }
  iv_reset(iv);
  //=====> 6. Run Verify GCM circuit and judge the result <=====
  OPENSSL_memcpy(block.begin(), in.begin() + plaintext_len, tag_len);
  Util::print_hex_data(iv, "EK0 IV");
  Util::print_hex_data(block, "server_tag");
  Util::print_hex_data(gcm_block, "Tagshare");
  run_gcm_tag_circuit<false>(ssl->make_tag_circuit, ssl->verify_tag_circuit,
                             ssl->aes_joint_circuit, ssl->server_key_share, iv,
                             gcm_block, block, masked_out_block);
  if (masked_out_block[0] == 0 || masked_out_block[1] == 0) {
    fprintf(stderr, "[Prover] Can not decrypt message, flag: %d%d\n",
            masked_out_block[0], masked_out_block[1]);
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
    return false;
  }
  //=====> 7. Decrypt the last block and judge if type is Application Data
  //<=====
  last_block_start = get_last_block_info(plaintext_len, iv);
  block.fill(0);
  std::copy(in.begin() + last_block_start, in.begin() + plaintext_len,
            block.begin());
  Util::print_hex_data(iv, "IV");
  if (!aes_ctr(ssl, ssl->server_key_share, iv, block, masked_out_block))
    return false;
  OPENSSL_memcpy(in.begin() + last_block_start, masked_out_block.begin(),
                 plaintext_len - last_block_start);
  if (in[plaintext_len - 1] != SSL3_RT_APPLICATION_DATA) {
    in[0] = 0x17;
    *out = in.subspan(0, 1);
    return true;
  }
  //=====> 8. Now call aes_ctr to run 2PC circuit and decrypt <=====
  iv_reset(iv, 2);
  for (size_t i = 0; i + 15 < last_block_start; i += 16) {
    OPENSSL_memcpy(block.begin(), in.begin() + i, block.size());
    // Util::generate_random_bytes(mask);
    // Util::xor_func(mask.begin(), block.begin(), block.size());
    if (!aes_ctr(ssl, ssl->server_key_share, iv, block, masked_out_block))
      return false;
    iv_incr(iv);
    OPENSSL_memcpy(in.begin() + i, masked_out_block.begin(),
                   masked_out_block.size());
  }
  //=====> 8. Output the plaintext, notice that we have removed the suffix tag
  //<=====
  *out = in.subspan(0, plaintext_len);
  printf("[Prover] Run 2PC aes_decrypt successful!\n");
  return true;
}

void ThreePartyrEncrypt::preproc_all_aes_gcm_circuits(SSL *ssl,
                                                      bool single) noexcept {
  if (!ssl->verifier)
    return;
  if (!ssl->aes_joint_circuit || !ssl->make_tag_circuit ||
      !ssl->verify_tag_circuit)
    return;
  EmpWrapperAG2PC::preproc_aes_gcm_circuits(ssl->make_tag_circuit,
                                            ssl->verify_tag_circuit,
                                            ssl->aes_joint_circuit, single);
}

bool ThreePartyrEncrypt::commit_email_address(SSL *ssl,
                          std::array<uint8_t, 16*EmpWrapperAG2PCConstants::COMMIT_INPUT_BLOCK_NUM> &email_address,
                          std::array<uint8_t, 16> &random_val) noexcept {
  if (!ssl || !ssl->verifier) {
    current_state = STATE_ERROR;
    return false;
  }
  SSL *verifier = ssl->verifier;
  auto begin_commit_proc = std::chrono::steady_clock::now();
  if (!ssl->commit_circuit) {
    ssl->commit_circuit = EmpWrapperAG2PC::build_commit_circuit(
        verifier, emp::BOB, EmpWrapperAG2PCConstants::COMMIT_CIRCUIT_TAG);
    if (!ssl->commit_circuit) {
      current_state = STATE_ERROR;
      return false;
    }
    ssl->commit_circuit->do_preproc();
  }
  auto end_commit_proc = std::chrono::steady_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::duration<double>>(
      end_commit_proc - begin_commit_proc);
  printf("Commitment Offline Time: %.6f\n",duration.count());
  
  std::array<uint8_t, 16*EmpWrapperAG2PCConstants::COMMIT_INPUT_BLOCK_NUM> outaes;
  std::array<uint8_t, 16> iv{};
  std::array<uint8_t, 32> outhash;
  // Calculate iv
  uint8_t sequence[8];
  //0: EHLO / 1: AUTH LOGIN / 2: Base64(email_address)
  CRYPTO_store_u64_be(sequence, 2);
  OPENSSL_memcpy(iv.begin() + 4, sequence, 8);
  Util::xor_func(ssl->client_iv.begin(), iv.begin(), 12);
  iv[15] = 2;
  Util::print_hex_data(iv, "IV of commit: ");
  auto begin_commit = std::chrono::steady_clock::now();
  // Run 2PC
  if(!run_commit_circuit(ssl->commit_circuit, ssl->client_key_share, iv, email_address, random_val, outhash, outaes))
    current_state = STATE_ERROR;
    return false;
  auto end_commit = std::chrono::steady_clock::now();
  duration = std::chrono::duration_cast<std::chrono::duration<double>>(
      end_commit - begin_commit);
  printf("Commitment Online Time: %.6f\n",duration.count());
  Util::print_hex_data(outhash, "SHA256 of commit: ");
  Util::print_hex_data(outaes, "AES of commit: ");

  return true;
}

bool TLSSocket::connect_to_verifier_and_set_ssl_callback(
    TLSSocket &connection_to_server, const std::string &address,
    const uint16_t port_number, bool single) noexcept {
  set_ip_v4();
  for (auto &i : socket_circuits) {
    i.reset(new TLSSocket(ssl_ctx, false));
    i->set_ip_v4();
    if (i->connect_to(address, port_number) == false) {
      warn("connecting to verifier on %s:%d failed!", address.c_str(),
           port_number);
      current_state = STATE_ERROR;
      return false;
    };
  }
  if (!connect_to(address, port_number) ||
      !is_correct_header<Messaging::MessageHeaders::DONE_HS>(ssl)) {
    warn("connecting to verifier on %s:%d failed!", address.c_str(),
         port_number);
    current_state = STATE_ERROR;
    return false;
  }
  puts("[Prover] Connected to verifier");
  // Set all the stuff up.
  if (!set_verifier_connection(connection_to_server.get_ssl_object())) {
    warn("Setting verifier failed");
    current_state = STATE_ERROR;
    return false;
  }
  connection_to_server.set_make_circuits();
  current_state = STATE_CONNECTED_VERIFIER;
  if (connection_to_server.set_handshake_callback() &&
      connection_to_server.set_keyshare_callback() &&
      connection_to_server.set_derive_shared_secret_callback() &&
      connection_to_server.set_derive_handshake_keys_callback() &&
      connection_to_server.set_commit_to_server_certificate_callback() &&
      connection_to_server.set_write_h6_callback() &&
      connection_to_server.set_derive_traffic_keys_callback() &&
      connection_to_server.set_derive_gcm_shares_callback() &&
      connection_to_server.set_send_handshake_data_callback(
          &ThreePartyrEncrypt::send_handshake_data) &&
      connection_to_server.set_aes_encrypt(
          &ThreePartyrEncrypt::aes_encrypt_from_ssl) &&
      connection_to_server.set_aes_decrypt(
          &ThreePartyrEncrypt::aes_decrypt_from_ssl) &&
      ThreePartyHandshake::preproc_circuits_before_handshake(
          connection_to_server.get_ssl_object(), single)) {
    return true;
  }
  warn("Setting callbacks failed");
  current_state = STATE_ERROR;
  return false;
}

bool TLSSocket::set_fd_and_handshake(const int sock) noexcept {
  BIO *bio = BIO_new_socket(connection, BIO_CLOSE);
  SSL_set_bio(ssl, bio, bio);
  return SSL_connect(ssl) > 0;
}

/*================== Cut Here ==================== *
 * NOTICE: Next is the record layer encryption and *
 * decryption process performed by the verifier.   *
 * =============================================== */

// encrypt one block
bool Server::aes_ctr(const std::array<uint8_t, 16> &key,
                     const std::array<uint8_t, 16> &iv,
                     std::array<uint8_t, 16> &out) noexcept {

  EmpWrapperAG2PCConstants::AESCircuitJointIn input;
  input.key = key;
  input.iv = iv;
  EmpWrapperAG2PCConstants::AESCircuitJointOut output;

  if (!ThreePartyrEncrypt::run_aes_joint_circuit(input, output,
                                                 aes_joint_circuit.get())) {
    return false;
  }
  if (!output.cheated) {
    return false;
  }
  out = output.pt;
  return true;
}

bool Server::read_ad_data(std::vector<uint8_t> &ad,
                          uint8_t sequence[8]) noexcept {
  uint64_t ad_length, buf;
  CBS in_cbs;
  auto amount_read = socket.read(&buf, sizeof(uint64_t));
  if (amount_read <= 0 || amount_read != static_cast<int>(sizeof(uint64_t))) {
    return false;
  }
  CBS_init(&in_cbs, reinterpret_cast<const uint8_t *>(&buf), sizeof(uint64_t));
  CBS_get_u64(&in_cbs, &ad_length);
  ad.resize(ad_length);
  amount_read = socket.read(ad.data(), static_cast<int>(ad_length));
  if (amount_read <= 0 || amount_read != static_cast<int>(ad_length)) {
    return false;
  }
  constexpr int sequence_length = 8;
  if (sequence_length != socket.read(sequence, sequence_length)) {
    return false;
  }
  Util::print_hex_data(ad, "Received AD data: ");
  return true;
}
// Read the ciphertext from prover
bool Server::read_ciphertext_and_commit(std::vector<uint8_t> &in) noexcept {
  auto amount_read = socket.read(in.data(), static_cast<int>(in.size()));
  if (amount_read <= 0 || amount_read != static_cast<int>(in.size())) {
    return false;
  }
  Util::print_hex_data(in, "Received ciphertext");
  return true;
}

bool Server::aes_gcm_encrypt() noexcept {
  puts("[Verifier] Call aes_gcm_encrypt(), running 2PC process...");
  //=====> 1. Get ad and from prover <=====
  uint8_t sequence[8];
  std::vector<uint8_t> ad;
  std::array<uint8_t, 16> iv{}, block{}, gcm_block{};
  read_ad_data(ad, sequence);
  size_t ad_length = ad.size(), i;
  size_t plaintext_len =
      CRYPTO_bswap2(*reinterpret_cast<uint16_t *>(ad.data() + ad_length - 2)) -
      16;
  //=====> 2. Prepare for calculating GCM tag <=====
  size_t gcm_power = ThreePartyrEncrypt::get_max_gcm_power(plaintext_len);
  auto muilt_and_xor_to_out = [&]() {
    ThreePartyrEncrypt::mult_H_power(block,
                                     client_gcm_powers.begin() + gcm_power);
    Util::xor_func(block.begin(), gcm_block.begin(), gcm_block.size());
    gcm_power -= 16;

  };
  //=====> 3. Set IV <=====
  std::copy(sequence, sequence + 8, iv.begin() + 4);
  // We use ad length to judge TLS version
  // TODO: Set a global boolean variable to judge
  if (ad_length == 5) {
    Util::xor_func(traffic_key_shares.client_iv.begin(), iv.begin(), 12);
  } else {
    // TODO: TLS 1.2 IV
  }
  iv[15] = 2;
  //=====> 4. Do 2PC AES encrypt and generate tag at the same time <=====
  std::copy(ad.begin(), ad.end(), block.begin());
  for (i = 0; i < plaintext_len; i += 16) {
    std::cin.sync();
    muilt_and_xor_to_out();
    if (!aes_ctr(traffic_key_shares.client_key_share, iv, block))
      return false;
    encrypted_data.push_back(block);
    Util::print_hex_data(block, "aes_block");
    size_t round_end = min(i + 16, static_cast<size_t>(plaintext_len)) - i;
    if (round_end < 16) {
      std::fill(block.begin() + round_end, block.end(), 0);
    }
    iv_incr(iv);
  }
  muilt_and_xor_to_out();
  CRYPTO_store_u64_be(block.begin(), ad.size() * 8);
  CRYPTO_store_u64_be(block.begin() + 8, plaintext_len * 8);
  muilt_and_xor_to_out();
  //=====> 5. Run make GCM Tag circuit and judge the result <=====
  iv_reset(iv);
  ThreePartyrEncrypt::run_gcm_tag_circuit<true>(
      gcm_tag_circuit.get(), gcm_verify_circuit.get(), aes_joint_circuit.get(),
      traffic_key_shares.client_key_share, iv, gcm_block, block, gcm_block);
  puts("[Verifier] Run 2PC AES-GCM encrypt successful!   ");
  return true;
}

bool Server::aes_gcm_decrypt() noexcept {
  puts("[Verifier] Call aes_gcm_decrypt(), running 2PC process...");
  //=====> 1. Get ad data from prover <=====
  std::vector<uint8_t> ad;
  uint8_t sequence[8];
  read_ad_data(ad, sequence);
  size_t ad_length = ad.size(), last_block_start, i;
  //=====> 2. Read cipher text from prover <=====
  size_t plaintext_len_all =
      CRYPTO_bswap2(*reinterpret_cast<uint16_t *>(ad.data() + ad_length - 2));
  decrypted_msg.resize(plaintext_len_all);
  read_ciphertext_and_commit(decrypted_msg);
  size_t plaintext_len = plaintext_len_all - 16;
  //=====> 3. Prepare for calculating GCM tag <=====
  size_t gcm_power = ThreePartyrEncrypt::get_max_gcm_power(plaintext_len);
  // We use ad length to judge TLS version
  // TODO: Set a global boolean variable to judge
  std::array<uint8_t, 16> iv{}, block{}, gcm_block{};

  auto muilt_and_xor_to_out = [&]() {
    ThreePartyrEncrypt::mult_H_power(block,
                                     server_gcm_powers.begin() + gcm_power);
    Util::xor_func(block.begin(), gcm_block.begin(), gcm_block.size());
    gcm_power -= 16;

  };
  //=====>  4. Now calculate GCM tag share <=====
  std::copy(ad.begin(), ad.end(), block.begin());
  muilt_and_xor_to_out();
  for (i = 0; i < plaintext_len; i += 16) {
    size_t round_end = min(i + 16, plaintext_len) - i;
    if (round_end < 16) {
      std::fill(block.begin() + round_end, block.end(), 0);
    }
    OPENSSL_memcpy(block.begin(), decrypted_msg.data() + i, round_end);
    // Xor ciphertext
    muilt_and_xor_to_out();
  }
  CRYPTO_store_u64_be(block.begin(), ad.size() * 8);
  CRYPTO_store_u64_be(block.begin() + 8, plaintext_len * 8);
  muilt_and_xor_to_out();
  //=====> 5. Set iv <=====
  std::copy(sequence, sequence + 8, iv.begin() + 4);
  if (ad_length == 5) {
    Util::xor_func(traffic_key_shares.server_iv.begin(), iv.begin(), 12);
  } else {
    // TODO: TLS 1.2 IV
  }
  iv_reset(iv);
  //=====> 6. Run Verify GCM circuit and judge the result <=====
  std::copy(decrypted_msg.begin() + plaintext_len, decrypted_msg.end(),
            block.begin());
  // Call verify tag circuit
  std::array<uint8_t, 16> out_flag;
  ThreePartyrEncrypt::run_gcm_tag_circuit<false>(
      gcm_tag_circuit.get(), gcm_verify_circuit.get(), aes_joint_circuit.get(),
      traffic_key_shares.server_key_share, iv, gcm_block, block, out_flag);
  if (out_flag[0] == 0 || out_flag[1] == 0) {
    fprintf(stderr,
            "[Verifier] Can not decrypt message from prover, flag: %d%d\n",
            out_flag[0], out_flag[1]);
    return false;
  }
  //=====> 7. Decrypt the last block and judge if type is Application Data
  //<=====
  last_block_start = get_last_block_info(plaintext_len, iv);
  Util::print_hex_data(iv, "IV");
  if (!aes_ctr(traffic_key_shares.server_key_share, iv, block))
    return false;
  if (block[plaintext_len - last_block_start - 1] != SSL3_RT_APPLICATION_DATA) {
    decrypted_msg.clear();
    return true;
  }
  OPENSSL_memcpy(decrypted_msg.data() + last_block_start, block.begin(),
                 plaintext_len - last_block_start);
  //=====> 8. Now call aes_ctr to run 2PC circuit and decrypt <=====
  iv_reset(iv, 2);
  for (i = 0; i + 15 < last_block_start; i += 16) {
    if (!aes_ctr(traffic_key_shares.server_key_share, iv, block))
      return false;
    OPENSSL_memcpy(decrypted_msg.data() + i, block.begin(), block.size());
    Util::print_hex_data(block, "aes_block");
    iv_incr(iv);
  }
  decrypted_msg.resize(plaintext_len);
  puts("[Verifier] Run 2PC AES-GCM decrypt successful!   ");
  return true;
}

int verifier_certificate_callback(int preverify_ok, X509_STORE_CTX *ctx) {
  X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
  // We print the certifate info during debug period
  // X509_print_fp(stdout, cert);
  X509_NAME* subject_name =  X509_get_subject_name(cert);
  // printf("\e[37mCertificate Subject: ");
  // X509_NAME_print_ex_fp(stdout, subject_name, 0, XN_FLAG_COMPAT);
  // puts("\e[0m");
  return preverify_ok;
}

bool Server::read_handshake_data() noexcept {
  // Read sequence, encrypted SC & SCV and SHTS & CHTS from prover
  if (!read_transcript_data(transcript,
                            Messaging::MessageHeaders::ENC_HANDSHAKE_SEND)) {
    puts("[Verifier] Failed to read data in read_handshake_data");
    return false;
  }
  // Verify the commit hash
  auto transcript_end_p = transcript.data() + transcript.size();
  constexpr auto SHARE_LEN = 16;
  constexpr auto hash_size = 32; // SHA-256 Hash.
  unsigned out_len{};
  uint8_t prover_hash_cur[hash_size];
  bssl::Span<uint8_t> shts_c =
      bssl::MakeSpan(transcript_end_p - SHARE_LEN, SHARE_LEN);
  bssl::Span<uint8_t> chts_c =
      bssl::MakeSpan(transcript_end_p - 2 * SHARE_LEN, SHARE_LEN);
  bssl::ScopedEVP_MD_CTX hash_{};
  if (!EVP_DigestInit_ex(hash_.get(), EVP_sha256(), nullptr) ||
      !EVP_DigestUpdate(hash_.get(), chts_c.data(), chts_c.size()) ||
      !EVP_DigestUpdate(hash_.get(), shts_c.data(), shts_c.size()) ||
      !EVP_DigestFinal_ex(hash_.get(), prover_hash_cur, &out_len) ||
      out_len != hash_size) {
    puts("[Verifier] Failed calc hash in read_handshake_data");
    return false;
  }
  if (OPENSSL_memcmp(prover_hash_cur, chts_shts_comm.data(), hash_size)) {
    puts("[Verifier] The SHTS & CHTS commitment open failed!");
    return false;
  }
  // Now we are initializing the SSL structure
  SSL_CTX *ctx = SSL_CTX_new(TLS_method());
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verifier_certificate_callback);
  SSL_CTX_set_default_verify_paths(ctx);
  // Notice: the line below must be disabled in the manufacturing environment
  X509_STORE_load_locations(ctx->cert_store, "../TestFreeAuth/TestCA/certs/ca_root.crt",
                            NULL);
  // Notice End
  verify_fake_ssl = SSL_new(ctx);
  SSL_CTX_free(ctx);
  SSL_set_connect_state(verify_fake_ssl);
  bssl::ssl_reset_error_state(verify_fake_ssl);
  verify_fake_ssl->s3->early_data_reason = ssl_early_data_disabled;
  verify_fake_ssl->version = TLS1_3_VERSION;
  verify_fake_ssl->s3->have_version = true;
  verify_fake_ssl->s3->aead_read_ctx->SetVersionIfNullCipher(
      verify_fake_ssl->version);
  bssl::SSL_HANDSHAKE *hs = verify_fake_ssl->s3->hs.get();
  verify_fake_ssl->cipher_suite = 0x1301; // TLS_AES_128_GCM_SHA256
  hs->new_cipher = SSL_get_cipher_by_value(verify_fake_ssl->cipher_suite);
  ssl_get_new_session(hs);
  hs->new_session->cipher = hs->new_cipher;
  hs->transcript.InitHash(verify_fake_ssl->version, hs->new_cipher);
  hs->ResizeSecrets(hash_size);
  if (hs == nullptr) {
    puts("[Error] read_handshake_data(): hs is null!");
    return false;
  }
  // Try to copy CHTS and SHTS from received data
  auto chts = hs->client_handshake_secret();
  auto shts = hs->server_handshake_secret();
  OPENSSL_memcpy(shts.data(), shts_c.data(), SHARE_LEN);
  OPENSSL_memcpy(shts.data() + SHARE_LEN,
                 handshake_key_shares.SHTS_share.data(), SHARE_LEN);
  OPENSSL_memcpy(chts.data(), chts_c.data(), SHARE_LEN);
  OPENSSL_memcpy(chts.data() + SHARE_LEN,
                 handshake_key_shares.CHTS_share.data(), SHARE_LEN);
  // Use full recoverd SHTS to generate handshake key
  bssl::tls13_set_traffic_key(verify_fake_ssl, ssl_encryption_handshake,
                              evp_aead_open, hs->new_session.get(), shts);
  Messaging::MessageHeaders header =
      Messaging::MessageHeaders::ENC_HANDSHAKE_SEND;
  while (header == Messaging::MessageHeaders::ENC_HANDSHAKE_SEND) {
    write_single_header(socket, Messaging::MessageHeaders::ENC_HANDSHAKE_RECV);
    constexpr auto HEADER_LEN = 5;
    bssl::Span<uint8_t> body;
    transcript.resize(transcript.size() - 2 * SHARE_LEN);
    // Decrypt the body in-place.
    if (!verify_fake_ssl->s3->aead_read_ctx->Open(
            &body, SSL3_RT_APPLICATION_DATA, TLS1_2_VERSION,
            verify_fake_ssl->s3->read_sequence,
            bssl::MakeConstSpan(transcript.data(), HEADER_LEN),
            bssl::MakeSpan(transcript.data() + HEADER_LEN,
                           transcript.size() - HEADER_LEN))) {
      puts("[Error] Can't decrypt handshake data in "
           "verify_server_certificate()");
      return false;
    }
    if (!bssl::ssl_record_sequence_update(verify_fake_ssl->s3->read_sequence,
                                          8)) {
      return true;
    }
    body = body.subspan(0, body.size() - 1);
    Util::print_hex_data(body, "Decrypt handshake data");
    if (!tls_append_handshake_data(verify_fake_ssl, body) ||
        !read_single_header(socket, header)) {
      return false;
    }
    // get next handshake data
    if (header == Messaging::MessageHeaders::ENC_HANDSHAKE_SEND) {
      uint64_t size;
      read_single_u64(socket, size);
      transcript.clear();
      transcript.reserve(size);
      do {
        const auto read =
            socket.read(buffer.data(), static_cast<int>(buffer.size()));
        if (read <= 0) {
          // We failed to read.
          return false;
        }

        // The buffer is already at the right size, so this will not cause
        // allocations.
        transcript.insert(transcript.end(), buffer.begin(),
                          buffer.begin() + read);
      } while (socket.pending() != 0);
    }
  }
  state = static_cast<Server::ServerState>((static_cast<uint8_t>(state) + 1));
  return true;
}

bool Server::verify_server_certificate() noexcept {
  bssl::SSL_HANDSHAKE *hs = verify_fake_ssl->s3->hs.get();
  // Set handshake state to directly enter do_read_encrypted_extensions()
  hs->tls13_state = 3; // state_read_encrypted_extensions
  // Now set H3 data received from prover into SSL transcript
  // so we can call ssl_public_key_verify() to verify SCV
  hs->transcript.SetHashValueForVerifier(h3h4.data(), h3h4.size() / 2, 2);
  hs->extensions.sent = 0xffffffff; // Make all extensions sent
  // Verify SC and SCV data are all behind tls13_client_handshake()
  if (tls13_client_handshake(hs) != bssl::ssl_hs_flush ||
      hs->tls13_state != 14) // state_done
  {
    printf("[Error] Can't process handshake data in "
           "verify_server_certificate(), state = %d\n",
           hs->tls13_state);
    return false;
  }
  // Release the transcript and finish the process
  transcript.clear();
  SSL_shutdown(verify_fake_ssl);
  SSL_free(verify_fake_ssl);
  write_single_header(socket,
                      Messaging::MessageHeaders::SERVER_CERTIFICATE_PASS);
  state = static_cast<Server::ServerState>((static_cast<uint8_t>(state) + 1));
  return true;
}

bool Server::decrypt_finished_callback() {
  static uint8_t exit_command[] = {0x1b, 0x71, 0x00,
                                   0x17}; // Press 'Esc', release, press 'q'
  if (decrypted_msg.size() == sizeof(exit_command) &&
      !OPENSSL_memcmp(exit_command, decrypted_msg.data(),
                      decrypted_msg.size())) {
    should_exit = true;
    return true;
  }
  puts("==========Decrypted msg==========");
  fwrite(decrypted_msg.data(), decrypted_msg.size(), 1, stdout);
  putchar('\n');
  Util::print_hex_data(decrypted_msg);
  return true;
}

/*================== Cut Here ==================== *
 * NOTICE: Next is the functions used in stating   *
 * =============================================== */

std::pair<size_t, size_t> get_bandwith_from_single_ssl(SSL *ssl) noexcept {
  BIO *bio = SSL_get_rbio(ssl);
  auto rnum = BIO_number_read(bio);
  bio = SSL_get_wbio(ssl);
  auto wnum = BIO_number_written(bio);
  return std::make_pair(rnum, wnum);
}

std::pair<size_t, size_t> get_bandwith_from_ssl(TLSSocket &sock) noexcept {
  SSL *ssl = sock.get_ssl_object();
  if (!ssl->verifier) {
    puts("get_bandwith_from_ssl(): No verifier!");
    return std::make_pair(0, 0);
  }
  auto res = get_bandwith_from_single_ssl(ssl->verifier);
  if (ssl->socket_circuits) {
    for (int i = 0; i < CIRCUIT_NUM; i++) {
      auto tmp = get_bandwith_from_single_ssl(ssl->socket_circuits[i]);
      res.first += tmp.first;
      res.second += tmp.second;
    }
  }
  return res;
}
