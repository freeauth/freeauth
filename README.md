# FreeAuth

FreeAuth is a novel universal and privacy-enhanced email ownership verification scheme that allows users to selectively disclose information associated with their email addresses. The submitted artifact includes the FreeAuth prototype and a prototype of an integrated email client, which mainly displays email ownership authentication, commitment generation, and statement generation. Section 5 of the accepted paper presents the test results of these features. We will submit the complete FreeAuth prototype code along with a virtual machine image containing the correctly compiled binaries.

## Overview

This submitted artifact includes the complete code for the FreeAuth prototype and showcases its three main features: email ownership authentication, commitment generation and statement generation.

It is worth noting that FreeAuth is designed to support TLSv1.2 and TLSv1.3 connections, and is compatible with three email transmission protocols: SMTP, IMAP and POP3, as well as three authentication protocols: PLAIN, LOGIN and XOAUTH2. 

However, as mentioned in the submitted artifact, in the prototype we focus on adapting to TLSv1.3 and showcase all the features of FreeAuth based on SMTP protocol.

A comparison of support is as follows:

|                             | Prototype Support   | Scheme Support      |
| --------------------------- | ------------------- | ------------------- |
| TLS Version                 | TLSv1.3             | TLSv1.3,TLSv1.2     |
| email transmission protocol | SMTP                | SMTP, IMAP, POP3    |
| authentication method       | PLAIN,LOGIN,XOAUTH2 | PLAIN,LOGIN,XOAUTH2 |

In order to adapt the FreeAuth prototype to TLSv1.2, additional development work is required.

However，The prototype does not require additional development for IMAP and POP3, but it does require the user to design an ideal interaction template according to the corresponding transmission protocol (see Section 3.3  in the artical for more details), and then complete the specific interaction steps according to the template.

## Components

FreeAuth is primarily concerned with interactions between three parties (see Section 3.1 for more details)：

- **Prover(Client)**: Prover is the entity seeking to demonstrate ownership of a specific email account to the verifier, and participates in email ownership authentication, commitment generation, and statement generation.
- **Verifier:** Verifier represents the applications or services interested in confirming the ownership of a client’s email address, and participates in email ownership authentication, commitment generation.
- **Server:** Server refers to any email service provider (e.g. Gmail, Outlook, etc.), and only participates in email ownership authentication. Meanwhile, Server does not need to make any changes for FreeAuth.

We categorize and demonstrate the functionality of FreeAuth into three parts: email ownership authentication, commitment generation, and statement generation:

- **Email Ownership Authentication:**  In this section, the Prover connects with the Verifier using TLS Oracle, followed by a connection with the Server for standard email authentication. The core functions are implemented in **FreeAuth/TestSMTP*.cpp**. Further details of the function can be found in Section 3.4.
- **Commitment Generation:**  In this section, the Prover interacts with the Verifier and generates a commitment to the data exchanged during the email ownership authentication process. The core functions are implemented in **FreeAuth/TestSingleCommit*.cpp**. Further details of the function can be found in Appendix F.1.
- **Statement Generation：**In this section, the  Prover independently selectively discloses information related to email addresses through non-interactive zero-knowledge proofs(ZKPs). The core functions are implemented in **FreeAuth/StatementGenaration**. Further details of the function can be found in Appendix F.2.

We provide a demo of a third-party email client to demonstrate our email ownership authentication process. The core functions are implemented in **FreeAuth/ApplicationDemo**

## Structure

**FreeAuth/:** This folder contains the main FreeAuth code.

- **FreeAuth/Lib*:** These files contain the implementation of FreeAuth's base functionality, including 2PC-AES-GCM and more. 
- **FreeAuth/TestSMTP*:** These files contain the implementation of email ownership authentication for Prover, Verifier and Server. A local presentation of the email ownership authentication functionality can be achieved by running these three files.
- **FreeAuth/TestSingleCommit*:** These files contain the implementation of commitment generation for Prover and Verifier.  A local presentation of the commitment generation functionality can be achieved by running these two files. 
- **FreeAuth/StatementGeneration:** This folder contains zero-knowledge proof code for three statements generation based on [arkworks-rs](https://github.com/arkworks-rs/groth16.git). A local presentation of  zero-knowledge proof generation for the three statements can be achieved by running the code.
- **FreeAuth/ApplicationDemo:** This folder contains the email client demo based on VUE3.js and Electron, integrated with FreeAuth's email ownership authentication.

**boringssl/:** This directory contains a tweaked version of  [BoringSSL](https://github.com/google/boringssl.git). BoringSSL is a fork of OpenSSL that is designed to meet Google's needs. DiStefano uses BoringSSL for TLS functionality, so we inherited it and made some more modifications for FreeAuth.

**Distefano/:**  This directory contains a tweaked version of [Distefano](https://github.com/brave-experiments/DiStefano.git). We primarily adopted the mechanism outlined by DiStefano to implement the TLS Oracle functions within FreeAuth.

**emp/:** This directory contains a tweaked version of emptool-kit(including [emp-ot](https://github.com/emp-toolkit/emp-ot.git), [emp-ag2pc](https://github.com/emp-toolkit/emp-ag2pc.git) and [emp-tool](https://github.com/emp-toolkit/emp-tool.git)). FreeAuth uses emp for all MPC functionality.

**2pc/:** This directory is a quick-access link to the Distefano/2pc/ folder and contains all the circuits and circuit generation files used in Distefano and FreeAuth.



## How to build

### Install dependencies

```
sudo apt update
sudo apt install build-essential
sudo apt -y install cmake make gcc g++ rustc cargo golang git libssl-dev
```

### Building FreeAuth

```
git clone https://github.com/didnet/Hades.git
cd freeauth
./build.sh
```

### Test and Benchmark

```
./run.sh
```

By running **run.sh**, we demonstrate email ownership authentication, commitment generation and statement generation in turn. The test results in Section 5.1 for the submitted article are derived from the same program run in our experimental setup.

In the submitted article test, our experimental setup is as follows:

- We conducted our evaluation on an Ubuntu 20.04 environment. The client was executed on a consumer-grade machine (Intel i7-11800H@3200MHz 16Core CPU and 16GB RAM ), In contrast, the Verifier and Server were run on server-grade machines (Virtualized Intel i9-13900K@7200MHz 32-Core CPU and Virtualized 16GB RAM). 
- To simulate both LAN and WAN environments, we controlled the network latency between nodes, establishing a round-trip time of approximately 4ms for LAN and 20ms for WAN, with a bandwidth of about 1 Gbps.

In order to make a better and faster presentation of the experimental results, for this test we only show the results of the same program running locally. Since there is no limitation on network bandwidth and latency, the local test results will be faster than the results shown in the submitted paper. <u>The results shown in the following sections are the results of local test runs on the VM resources provided by the committee</u> (4 cores, 16GB memory, 40GB Disk, Ubuntu 22.04).

- Approximate time to run **build.sh**: 2min54s
- Approximate time to run **run.sh**: 31.14s

**Test1: Email Ownership Authentication** 

We implemented this part using C++. In the test, Server performs the normal SMTP email server authentication and response, and Prover and Verifier jointly perform the PLAIN authentication mechanism to complete the ownership authentication. The test execution results are as follows, showing the flow of interaction between the three parties. 

Specific running instructions:

```
cd build
./TestSMTPServer
./TestSMTPVerifier
./TestSMTPProver
```

Specific test output:

```
Test1: Email Ownership Authentication
========================================
TestSMTPVerifier: no process found
TestSingleCommitVerifier: no process found
[Server] simple server listen on:127.0.0.1:18388
[Server] Alternatively, you can run the client program by pasting the following command into another terminal:
./TestSMTPProver -a 127.0.0.1 -s 18388 -v VERIFIER_PORT
[Verifier] verifier listen on: 127.0.0.1:18389
[Verifier] Accepting
[Verifier] Doing handshake
[Verifier] Finished handshake
[Verifier] Preprocessing circuits
[Prover] Connected to verifier
[derive_gcm_mult_shares.txt] offline time: 3.040599s
[derive_gcm_mult_shares.txt] offline time: 3.104828s
[Verifier] Preproc gcm share circuit... done
[derive_traffic_secrets_combined.txt] offline time: 3.972720s
[Verifier] Preproc traffic circuit... done
[derive_traffic_secrets_combined.txt] offline time: 3.911947s
[derive_handshake_secrets_256.txt] offline time: 4.102982s
[Verifier] Preproc HS1 circuit... done
[derive_handshake_secrets_256.txt] offline time: 4.001782s
[Verifier] Preproc all circuits cost 9.325852s
[Verifier] Reading key share
[Server] New client connect in: 127.0.0.1
[Verifier] Creating key share
[Verifier] Writing key share
[Verifier] Reading server key share
[Verifier] Finishing 3PH
[Verifier] Writing HS_RECV
[Verifier] Doing ectf
[Verifier] Finished ectf
[Verifier] Doing HS derivation
[derive_handshake_secrets_256.txt] online time: 0.091411s
[derive_handshake_secrets_256.txt] online time: 0.091502s
[Verifier] Finished HS derivation
[Verifier] Reading SHTS_c and CHTS_c commit
[Verifier] Send SHTS_v and CHTS_v to Prover
[Verifier] Reading SHTS_c & CHTS_c and encrypted SC & SCV data
[Verifier] Reading H3 for SCV and H4 for SF verification
[Verifier] Verify [ServerCertificate,ServerCertificateVerify,ServerFinished]
[Verifier] Deriving TS
[derive_traffic_secrets_combined.txt] online time: 0.065533s
[derive_traffic_secrets_combined.txt] online time: 0.065627s
[Verifier] Deriving GCM shares
[Verifier] Calling into derivation circuit
[derive_gcm_mult_shares.txt] online time: 0.005628s
[derive_gcm_mult_shares.txt] online time: 0.001788s
[derive_gcm_mult_shares.txt] online time: 0.040578s
[derive_gcm_mult_shares.txt] online time: 0.001877s
[Verifier] Derived GCM shares
==============Time data print==============
3HS prepare between prover and verifier time: 9.369561
Key share generation time: 0.000393
Key exchange result computation time: 0.369749
Handshake key derivation time: 0.141711
Verify handshake data time: 0.053336
AES key schedule time: 0.731550
TPH phase total: 10.666300
===========================================
[Verifier] Enter attest()
[Prover] Finished three party handshake
[Server] Finished handshake with client 4 32
[derive_gcm_tag.txt] offline time: 3.107260s
[derive_gcm_tag.txt] offline time: 3.143276s
[aes_ctr_joint.txt] offline time: 3.203177s
[Prover] Server connected. Now we begin send SMTP data packets
[Prover] Call 2PC aes_encrypt with 15 bytes, seq = 0
[aes_ctr_joint.txt] offline time: 3.167325s
[Verifier] Preproc aes gcm_tag gcm_cfy cost 3.949757s
[Verifier] Call aes_gcm_encrypt(), running 2PC process...
[aes_ctr_joint.txt] online time: 0.042498s
[aes_ctr_joint.txt] online time: 0.043503s
[derive_gcm_tag.txt] online time: 0.000225s
[derive_gcm_tag.txt] online time: 0.043689s
[Verifier] Run 2PC AES-GCM encrypt successful!
[Prover] Run 2PC aes_encrypt successful, now send the packet to Server
Send -> HELO emailreg
[Prover] Call 2PC aes_encrypt with 12 bytes, seq = 1
[Verifier] Call aes_gcm_encrypt(), running 2PC process...
[aes_ctr_joint.txt] online time: 0.000067s
[aes_ctr_joint.txt] online time: 0.000974s
[derive_gcm_tag.txt] online time: 0.041914s
[derive_gcm_tag.txt] online time: 0.086733s
[Verifier] Run 2PC AES-GCM encrypt successful!
[Prover] Run 2PC aes_encrypt successful, now send the packet to Server
Send -> AUTH LOGIN
[Prover] Call 2PC aes_encrypt with 22 bytes, seq = 2
[Verifier] Call aes_gcm_encrypt(), running 2PC process...
[aes_ctr_joint.txt] online time: 0.000064s
[aes_ctr_joint.txt] online time: 0.000976s
[aes_ctr_joint.txt] online time: 0.041981s
[aes_ctr_joint.txt] online time: 0.042851s
[derive_gcm_tag.txt] online time: 0.000128s
[derive_gcm_tag.txt] online time: 0.043854s
[Verifier] Run 2PC AES-GCM encrypt successful!
[Prover] Run 2PC aes_encrypt successful, now send the packet to Server
Send -> dXNlcm5hbWVAcXEuY29t
[Prover] Call 2PC aes_encrypt with 22 bytes, seq = 3
[Verifier] Call aes_gcm_encrypt(), running 2PC process...
[aes_ctr_joint.txt] online time: 0.000061s
[aes_ctr_joint.txt] online time: 0.000969s
[aes_ctr_joint.txt] online time: 0.042005s
[aes_ctr_joint.txt] online time: 0.042932s
[derive_gcm_tag.txt] online time: 0.000131s
[derive_gcm_tag.txt] online time: 0.043869s
[Verifier] Run 2PC AES-GCM encrypt successful!
[Prover] Run 2PC aes_encrypt successful, now send the packet to Server
Send -> eW91cl9wYXNzd29yZA==
```

Test results are shown:

```
==============Time data print==============
Preproc all handshake circuits before connect to server time costs: 9.369874
Three party handshake total time costs: 1.296978
Preproc AES-GCM-128 circuits time costs: 3.949461
Run threeparty SMTP auth proccess time costs: 0.351588
Total time costs: 14.967902
```

**Test2: Commitment Generation**

We implemented this part using C++. In this part Prover promises TLS encrypted data and outputs a SHA256 commitment result. In this test we commit a block of data (16 bytes), and outputs the time at which the commitment was generated.

Specific running commands:

```
cd build
./TestSingleCommitVerifier -p 18400
./TestSingleCommitProver -v 18400
```

Specific test output:

```
Test2: Commitment Generation
========================================
[derive_commitments_sha256_128.txt] offline time: 2.211645s
[derive_commitments_sha256_128.txt] offline time: 2.168892s
[derive_commitments_sha256_128.txt] online time: 0.090148s
[derive_commitments_sha256_128.txt] online time: 0.090140s
Commit time costs: 2.690933
```

**Test3: Statement Generation**

We implemented this part using Rust. Prover use commitment to generate three statements related to specific email address. The test implements statement generation and validation, and outputs the time at which the statements were generated.

Specific running commands:

```
cd build
./release/email
```

Specific test output:

```
Test3: Statement Generation
========================================
========Statement Example 1: Authentication of email domainsAuthentication of email domains=========
Creating parameters...
Creating proofs...
1.244783292 seconds
========Statement Example 2: Authentication of email addresses and generation of identifiers=========
Creating parameters...
Creating proofs...
2.488190542 seconds
========Statement Example 3: Authentication of email address=========
Creating parameters...
Creating proofs...
1.164136011 seconds
```



## Application Demo

We provide a demo of a third-party email client to demonstrate our email ownership authentication process. Provide users with visualized email ownership authentication services.

### How to build

```
sudo apt update
sudo apt install nodejs
```

### **How to run**

```
cd FreeAuth/ApplicationDemo
npm install
npm run serve
```









