#include "LibThreePartyEncrypt.h"
#include "ssl/TestUtil.hpp"
#include <arpa/inet.h>
#include <atomic>
#include <cstddef>
#include <unistd.h>
#include <cstdint>
#include <cstdlib>
#include <openssl/ssl.h>
#include <ssl/TLSSocket.hpp>
#include <string>
#include <thread>

extern std::atomic<int> current_state, need_decrypt;
#define BUFSIZE 1024
#define STATE_NOTHING 0
#define STATE_CONNECTED_VERIFIER 1
#define STATE_PREPROC_CIRCUITS_BEFORE_HANDSHAKE 2
#define STATE_DONE_THREE_PARTY_HANDSHAKE 3
#define STATE_PREPROC_CIRCUITS_FOR_AES_GCM 4
#define STATE_DONE_SMTP_PROCEDURE 5
#define STATE_COMMIT_DONE 6
#define STATE_COMPLETE 7
#define STATE_ERROR 8
char buf[BUFSIZE];
const char *verifier_ca_crt = "-----BEGIN CERTIFICATE-----\n\
MIIC9jCCAnygAwIBAgIUR5OomvZJa/MKZSWioffAyMzJW2UwCgYIKoZIzj0EAwIw\n\
gZ8xCzAJBgNVBAYTAkNOMRAwDgYDVQQIDAdCZWlqaW5nMRAwDgYDVQQHDAdIYWlk\n\
aWFuMRswGQYDVQQKDBJCZWloYW5nIFVuaXZlcnNpdHkxLzAtBgNVBAsMJlNjaG9v\n\
bCBvZiBDeWJlciBTY2llbmNlIGFuZCBUZWNobm9sb2d5MR4wHAYDVQQDDBVTZWN1\n\
cmUgRW1haWwgUmVnaXN0ZXIwHhcNMjQwNDE1MDYxNjU2WhcNMzQwNDEzMDYxNjU2\n\
WjCBnzELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0hh\n\
aWRpYW4xGzAZBgNVBAoMEkJlaWhhbmcgVW5pdmVyc2l0eTEvMC0GA1UECwwmU2No\n\
b29sIG9mIEN5YmVyIFNjaWVuY2UgYW5kIFRlY2hub2xvZ3kxHjAcBgNVBAMMFVNl\n\
Y3VyZSBFbWFpbCBSZWdpc3RlcjB2MBAGByqGSM49AgEGBSuBBAAiA2IABIXCTCd7\n\
QO8L/UpdXmbX+7tYj7KU02wFJ6/MkXojE3i6fXbGYnM0eAQaG9DKyy4P8qoizJPg\n\
MBCv/5RgzjZVclcsMys2jpQJ6IKYgnZEcvBj0ONMiJRCSzPz+XcFYjS+CKN3MHUw\n\
HQYDVR0OBBYEFKbPHYSDirzM/mX3oIODC3eWerlvMB8GA1UdIwQYMBaAFKbPHYSD\n\
irzM/mX3oIODC3eWerlvMA8GA1UdEwEB/wQFMAMBAf8wIgYDVR0RBBswGYIJbG9j\n\
YWxob3N0ggxjYS5lbWFpbC5jb20wCgYIKoZIzj0EAwIDaAAwZQIxAN+uvTmvNZZP\n\
mxJhNxFBpefi5DdTTbj8ufjfZb+oVARKZTNv4bbSsY1C09t7CQM04QIwfzEFc8Gb\n\
uojLN5KMgMcMY1djJHLANIW8mBbDih4vIUnkSFtozfrYDFKV6ymo1VRn\n\
-----END CERTIFICATE-----\n";

const char HELO_MESSAGE[] = "HELO emailreg\r\n",
           AUTH_LOGIN[] = "AUTH LOGIN\r\n";

struct VerifyDataModel {
  uint16_t verifier_port, smtp_port, smtp_method;
  std::string smtp_ip, verifier_ip, username, passwd;
};

extern "C" int get_current_state() { return current_state; }

bssl::UniquePtr<SSL_CTX> get_ssl_ctx_for_tls1_3() {
    SSL_library_init();
    SSL_load_error_strings();
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_default_verify_paths(ctx);
    auto ca_cert = CertFromPEM(verifier_ca_crt);
    X509_STORE_add_cert(ctx->cert_store, ca_cert.get());
    ctx->conf_min_version = 0x304;
    return bssl::UniquePtr<SSL_CTX>(ctx);
}

inline void socketRecvAndLog(TLSSocket &sock) 
{
    int len;
    if((len = sock.read(buf, BUFSIZE)) < 0) {
      current_state = STATE_ERROR;
      return;
    }
    for(int i = 0,flag = 1;i<len;i++) {
        if (buf[i] == '\r' || buf[i] == 0) {
            break;
        } else if(flag) {
            flag = 0;
            std::cerr<<"\e[31mRecv <- ";
        }
        putchar(buf[i]);
    }
    puts("\e[0m");
}

inline void socketSendAndLog(TLSSocket &sock,const void* buffer, const size_t leng) 
{
    if(!sock.write(buffer, leng)) {
      current_state = STATE_ERROR;
      return;
    }
    std::cout<<"\e[34mSend -> "<< (const char*)buffer << "\e[0m";
}

size_t base64encode(const std::string &input, char* output);
inline void sendBase64AndRecv(TLSSocket &sock,const std::string &content)
{
    size_t leng = base64encode(content, buf);
    buf[leng++] = '\r';
    buf[leng++] = '\n';
    buf[leng] = 0;
    socketSendAndLog(sock, buf, leng);
    if (current_state == STATE_ERROR) return;
    socketRecvAndLog(sock);
}

inline void sendAndRecv(TLSSocket &sock,const void* buffer, const size_t leng)
{
    socketSendAndLog(sock, buffer, leng);
    if (current_state == STATE_ERROR) return;
    socketRecvAndLog(sock);
}

void SMTP_LoginCoreProc(TLSSocket &sock, VerifyDataModel &regData) {
  int smtp_step = 0;
  while (smtp_step < 5) {
    switch (smtp_step) {
      case 0:
      socketRecvAndLog(sock);
      break;
      case 1:
      sendAndRecv(sock, HELO_MESSAGE, sizeof(HELO_MESSAGE) - 1);
      break;
      case 2:
      sendAndRecv(sock, AUTH_LOGIN, sizeof(AUTH_LOGIN) - 1);
      break;
      case 3:
      sendBase64AndRecv(sock, regData.username);
      break;
      case 4:
      sendBase64AndRecv(sock, regData.passwd);
      break;
    }
    smtp_step++;
    if (current_state == STATE_ERROR)
      return;
  }
}

void SMTP_PlainCoreProc(TLSSocket &sock, VerifyDataModel &regData) {
  int smtp_step = 0;
  std::string username = regData.username;
  while (smtp_step < 3) {
    switch (smtp_step) {
      case 0:
      socketRecvAndLog(sock);
      break;
      case 1:
      sendAndRecv(sock, HELO_MESSAGE, sizeof(HELO_MESSAGE) - 1);
      break;
      case 2:
      username.insert(username.begin(), 0);
      username.push_back(0);
      username.insert(username.end(), regData.passwd.begin(), regData.passwd.end());
      char *p = snprintf(buf, BUFSIZE, "AUTH PLAIN ") + buf;
      p += base64encode(username, p);
      p[0] = '\r', p[1] = '\n', p[2] = 0;
      sendAndRecv(sock, buf, strlen(buf));
      break;
    }
    smtp_step++;
    if (current_state == STATE_ERROR)
      return;
  }
}

void SMTP_XOauthCoreProc(TLSSocket &sock, VerifyDataModel &regData) {
  int smtp_step = 0;
  while (smtp_step < 3) {
    switch (smtp_step) {
      case 0:
      socketRecvAndLog(sock);
      break;
      case 1:
      sendAndRecv(sock, HELO_MESSAGE, sizeof(HELO_MESSAGE) - 1);
      break;
      case 2:
        std::string seq=std::string (1,'\1');
        std::string passcode="user="+regData.username+seq+"auth=Bearer "+regData.passwd+seq+seq;
        char *p = snprintf(buf, BUFSIZE, "AUTH XOAUTH2 ") + buf;
        p+=base64encode(passcode,p);
        p[0] = '\r', p[1] = '\n', p[2] = 0;
        sendAndRecv(sock, buf, strlen(buf));
        break;
    }
    smtp_step++;
    if (current_state == STATE_ERROR)
      return;
  }
}

void ThreepartySMTPCoreProcess(VerifyDataModel regData) {
  bssl::UniquePtr<SSL_CTX> ctx = get_ssl_ctx_for_tls1_3();
  TLSSocket connection_to_verifier(ctx.get(), false);
  TLSSocket connection_to_server(ctx.get(),false);
  connection_to_server.set_ip_v4();
  current_state = STATE_NOTHING;
  while(current_state != STATE_COMMIT_DONE) {
    switch (current_state) {
      case STATE_NOTHING:
      if(!connection_to_verifier.connect_to_verifier_and_set_ssl_callback(connection_to_server,
      regData.verifier_ip, regData.verifier_port)) {
        current_state = STATE_ERROR;
      }
      break;

      case STATE_PREPROC_CIRCUITS_BEFORE_HANDSHAKE:
      if(!connection_to_server.connect_to(regData.smtp_ip, regData.smtp_port)) {
        current_state = STATE_ERROR;
      }
      break;

      case STATE_DONE_THREE_PARTY_HANDSHAKE:
      ThreePartyrEncrypt::preproc_all_aes_gcm_circuits(connection_to_server.get_ssl_object());
      break;

      case STATE_PREPROC_CIRCUITS_FOR_AES_GCM:
      if (regData.smtp_method == 1) {
        SMTP_LoginCoreProc(connection_to_server, regData);
      } else if (regData.smtp_method == 2) {
        SMTP_PlainCoreProc(connection_to_server, regData);
      } else if (regData.smtp_method == 3) {
        SMTP_XOauthCoreProc(connection_to_server, regData);
      } else {
        current_state = STATE_ERROR;
      }
      break;

      case STATE_DONE_SMTP_PROCEDURE:
      // ThreePartyrEncrypt::commit_email_address(connection_to_server.get_ssl_object());
      break;

      default:
      return;
      break;
    }
    if(current_state == STATE_ERROR) { fflush(stderr); return; };
    current_state++;
  }
  fflush(stdout);
  connection_to_server.close();
  connection_to_verifier.close();
}

extern "C" bool node_entry_point(int verifier_port, int smtp_port,
                                 int smtp_method, char *smtp_ip,
                                 char *verifier_ip, char *username,
                                 char *passwd) {
  VerifyDataModel regData{static_cast<uint16_t>(verifier_port),
                          static_cast<uint16_t>(smtp_port),
                          static_cast<uint16_t>(smtp_method),
                          std::string(smtp_ip),
                          std::string(verifier_ip),
                          std::string(username),
                          std::string(passwd)};
  dup2(STDERR_FILENO, STDOUT_FILENO);
  std::thread task(ThreepartySMTPCoreProcess, std::move(regData));
  task.detach();
  printf("[Prover] Call from front, verifier_port=%d smtp_port=%d "
         "auth_method=%d\nsmtp_ip=%s verifier_ip=%s username=%s "
         "passwd=%c%c%c***\n",
         verifier_port, smtp_port, smtp_method, smtp_ip, verifier_ip, username,
         passwd[0], passwd[1], passwd[2]);
  fflush(stdout);
  return true;
}

size_t base64encode(const std::string &input, char* output) {
    static const char encoding_table[] = {
                'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
				'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
				'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
				'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
				'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
				'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
				'w', 'x', 'y', 'z', '0', '1', '2', '3',
				'4', '5', '6', '7', '8', '9', '+', '/' 
    };
    size_t i,j;
    for(i=0,j=0;i<input.length();) {
        int a = input[i++];
        int b = i < input.length() ? input[i++] : 0;
        int c = i < input.length() ? input[i++] : 0;
        a = (a << 8) | b;
        a = (a << 8) | c;
        // printf("a=%d, b=%d, c=%d\n",a,b,c);
        output[j++] = encoding_table[a >> 18];
        output[j++] = encoding_table[(a >> 12) & 63];
        output[j++] = encoding_table[(a >> 6) & 63];
        output[j++] = encoding_table[a & 63];
    }
    size_t len = j;
    switch (input.length() % 3) {
        case 1:
        output[--j] = '=';
        case 2:
        output[--j] = '=';
    }
    return len;
}