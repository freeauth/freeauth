/*
  This file exists to allow one to easily benchmark how long the 3P-HS takes in
  an end-to-end setting. At a high-level, this file similarly to the tests in
  Server.t.cpp: we simply run the 3P-HS forward between two parties.
*/

#include <getopt.h>

#include "common.h"
#include <cstdint>
#include <iostream>
#include <nodes/Server.hpp>
#include <ssl/TestUtil.hpp>
#include <string>

constexpr size_t STAGE_TOTAL_NUM = 7;
const char STAGE_NAMES[][50] = {"3HS prepare between prover and verifier",
                                "Key share generation",
                                "Key exchange result computation",
                                "Handshake key derivation",
                                "Verify handshake data",
                                "AES key schedule"};

class VerifierTest : Server {
private:
  bool need_commit;
  std::unique_ptr<EmpWrapperAG2PC> commit_circuit;

  time_point<std::chrono::steady_clock> time_point_phases[STAGE_TOTAL_NUM];
  size_t time_point_index = 0;

public:
  VerifierTest(bssl::UniquePtr<SSL_CTX> &&ctx, const std::string &ip_address,
               const bool is_ip_v6, const int backlog, const bool need_commit,
               const uint16_t port = 18389)
      : Server(std::move(ctx), ip_address, is_ip_v6, backlog, port),
        need_commit(need_commit) {}

  bool accept() noexcept {
    for (size_t i = 0; i < CIRCUIT_NUM; i++) {
      socket_circuits[i] = socket.accept_tlsconnection();
      if (socket_circuits[i] == nullptr)
        return false;
      if (i == 0) {
        time_point_phases[time_point_index++] =
            std::chrono::steady_clock::now();
      }
      if (socket_circuits[i]->do_handshake() != 1) {
        PRINT_IF_LOUD("Failed to do circuit socket handshake");
        return false;
      }
    }
    if (!socket.accept()) {
      return false;
    }
    this->state = ServerState::HANDSHAKE;
    return true;
  }

  bool run(const ServerState stop_state = ServerState::DONE,
           const bool print = true, const bool should_preproc = true) {
    this->state = ServerState::ACCEPT;
    this->loud = print;
    bool was_successful;
    while (static_cast<uint8_t>(this->state) <
           static_cast<uint8_t>(stop_state)) {
      switch (this->state) {
      case ServerState::ACCEPT:
        PRINT_IF_LOUD("Accepting");
        was_successful = accept();
        break;
      case ServerState::HANDSHAKE:
        PRINT_IF_LOUD("Doing handshake");
        was_successful = do_handshake();
        break;
      case ServerState::HANDSHAKE_DONE:
        PRINT_IF_LOUD("Finished handshake");
        was_successful = write_handshake_done();
        break;
      case ServerState::CIRCUIT_PREPROC:
        PRINT_IF_LOUD("Preprocessing circuits");
        was_successful = do_preproc(should_preproc);
        time_point_phases[time_point_index++] =
            std::chrono::steady_clock::now();
        break;
      case ServerState::READING_KS:
        PRINT_IF_LOUD("Reading key share");
        was_successful = read_keyshare_after_handshake();
        break;
      case ServerState::MAKING_KS:
        PRINT_IF_LOUD("Creating key share");
        was_successful = create_new_share();
        break;
      case ServerState::WRITING_KS:
        PRINT_IF_LOUD("Writing key share");
        was_successful = send_additive_share();
        time_point_phases[time_point_index++] =
            std::chrono::steady_clock::now();
        break;
      case ServerState::READING_SKS:
        PRINT_IF_LOUD("Reading server key share");
        was_successful = read_sks_keyshare();
        break;
      case ServerState::FINISHING_TPH:
        PRINT_IF_LOUD("Finishing 3PH");
        was_successful = finish_tph();
        break;
      case ServerState::READING_PSSKS:
        assert(false);
        std::abort();
      case ServerState::WRITING_HS_RECV:
        PRINT_IF_LOUD("Writing HS_RECV");
        was_successful = write_hs_recv();
        break;
      case ServerState::ECTF_WAIT:
        PRINT_IF_LOUD("Doing ectf");
        was_successful = do_ectf();
        break;
      case ServerState::ECTF_DONE:
        PRINT_IF_LOUD("Finished ectf");
        was_successful = finish_ectf();
        time_point_phases[time_point_index++] =
            std::chrono::steady_clock::now();
        break;
      case ServerState::KS_WAIT:
        PRINT_IF_LOUD("Doing HS derivation");
        was_successful = do_ks();
        break;
      case ServerState::KS_DONE:
        PRINT_IF_LOUD("Finished HS derivation");
        was_successful = write_ks_done();
        time_point_phases[time_point_index++] =
            std::chrono::steady_clock::now();
        break;
      case ServerState::SHTS_CHTS_C_WAIT:
        PRINT_IF_LOUD("Reading SHTS_c and CHTS_c commit");
        was_successful = read_chts_shts_commit();
        break;
      case ServerState::SHTS_CHTS_V_SEND:
        PRINT_IF_LOUD("Send SHTS_v and CHTS_v to Prover");
        was_successful = send_shts_chts();
        break;
      case ServerState::READING_HS_DATA:
        PRINT_IF_LOUD("Reading SHTS_c & CHTS_c and encrypted SC & SCV data");
        was_successful = read_handshake_data();
        break;
      case ServerState::H6_WAIT:
        PRINT_IF_LOUD("Reading H3 for SCV and H4 for SF verification");
        was_successful = read_h3h4();
        break;
      case ServerState::VERIFY_SERVER_CERT:
        PRINT_IF_LOUD(
            "Verify "
            "[ServerCertificate,ServerCertificateVerify,ServerFinished]");
        was_successful = verify_server_certificate();
        time_point_phases[time_point_index++] =
            std::chrono::steady_clock::now();
        break;
      case ServerState::DERIVE_TS:
        PRINT_IF_LOUD("Deriving TS");
        was_successful = derive_ts();
        break;
      case ServerState::GCM_SHARE_DERIVE:
        PRINT_IF_LOUD("Deriving GCM shares");
        was_successful = derive_gcm_shares();
        break;
      case ServerState::GCM_SHARE_DONE:
        PRINT_IF_LOUD("Derived GCM shares");
        was_successful = write_completed_derivation();
        time_point_phases[time_point_index++] =
            std::chrono::steady_clock::now();
        break;
      default:
        // We terminate here, because this implies a logic error on our
        // part.
        // Note: in a release build we could make this an unreachable.
        std::abort();
      }

      if (!was_successful) {
        break;
      }
    }

    if (print) {
      puts("==============Time data print==============");
      for (size_t i = 1; i < STAGE_TOTAL_NUM; i++) {
        auto duration =
            std::chrono::duration_cast<std::chrono::duration<double>>(
                time_point_phases[i] - time_point_phases[i - 1]);
        printf("%s time: %.6f\n", STAGE_NAMES[i - 1], duration.count());
      }
      auto dur = std::chrono::duration_cast<std::chrono::duration<double>>(
          time_point_phases[STAGE_TOTAL_NUM - 1] - time_point_phases[0]);
      printf("TPH phase total: %.6f\n", dur.count());
      puts("===========================================");
    }

    if (was_successful) {
      std::cout << "[Verifier] Enter attest()\n";
      was_successful = attest();
      if (was_successful && need_commit) {
        std::cout << "[Verifier] Enter commit() to receive prover commit\n";
        was_successful = commit();
      }
    }

    return was_successful;
  };

  bool attest() noexcept {
    Messaging::MessageHeaders header;
    bool worked = true;
    EmpWrapperAG2PC::preproc_aes_gcm_circuits(gcm_tag_circuit.get(),
                                              gcm_verify_circuit.get(),
                                              aes_joint_circuit.get());
    while (worked) {
      // Read the single header in from the other party.
      if (!read_single_header(socket, header)) {
        return false;
      }
      switch (header) {
      case Messaging::MessageHeaders::STOP:
        return true;
      case Messaging::MessageHeaders::AES_ENC:
        worked = aes_gcm_encrypt();
        break;
      case Messaging::MessageHeaders::AES_DEC:
        worked = aes_gcm_decrypt();
        if (worked && !decrypted_msg.empty()) {
          worked = decrypt_finished_callback();
          if (worked && should_exit) {
            return true;
          }
        }
        break;
      case Messaging::MessageHeaders::COMMIT:
        break;
      default:
        worked = false;
        break;
      }
    }
    return worked;
  }

  bool commit() noexcept {
    commit_circuit.reset(EmpWrapperAG2PC::build_commit_circuit(
        get_ssl(), emp::ALICE, EmpWrapperAG2PCConstants::COMMIT_CIRCUIT_TAG));
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
    Util::xor_func(traffic_key_shares.client_iv.begin(), iv.begin(), 12);
    iv[15] = 2;

    if (!ThreePartyrEncrypt::run_commit_circuit(
            commit_circuit.get(), traffic_key_shares.client_key_share, iv, outaes,
            iv, outhash, outaes))
      return false;
    Util::print_hex_data(outhash, "SHA256 of commit: ");
    Util::print_hex_data(outaes, "AES of commit: ");
    Util::print_hex_data(encrypted_data[email_block_seq], "Encrypted block: ");
    return true;
  }

  bool decrypt_finished_callback() {
    static const char *exit_command = "235";
    fwrite(decrypted_msg.data(), decrypted_msg.size(), 1, stdout);
    putchar('\n');
    Util::print_hex_data(decrypted_msg);
    if (decrypted_msg.size() >= strlen(exit_command) &&
        !strncmp(exit_command, reinterpret_cast<char *>(decrypted_msg.data()),
                 strlen(exit_command))) {
      should_exit = true;
    }
    return true;
  }
}; // Class VerifierTest

static bool server_run(VerifierTest &verifier) {
  auto worked = verifier.run(Server::ServerState::DONE, true, true);
  if (!worked) {
    onError("[Verifier] Three party handshake failed!");
  }
  return worked;
}

int main(int argc, char *argv[]) {
  std::string ip = "127.0.0.1";

  uint16_t verifier_port = 18389;

  const char *const short_opts = "a:p:";
  const option long_opts[] = {{"ip", required_argument, nullptr, 'a'},
                              {"verifier port", required_argument, nullptr, 'p'}};

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
  VerifierTest verifier(std::move(ctx), ip.c_str(), false, 1, false,
                        verifier_port);

  std::cerr << "[Verifier] verifier listen on: " << ip << ":" << verifier_port
            << std::endl;

  server_run(verifier);
}
