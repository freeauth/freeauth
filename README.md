# FreeAuth

FreeAuth(https://anonymous.4open.science/r/freeauth-543F) is a novel universal and privacy-enhanced email ownership verification scheme that allows users to selectively disclose information associated with their email addresses. The submitted artifact includes the FreeAuth prototype and a prototype of an integrated email client, which mainly accomplish email ownership authentication, commitment generation, and statement generation. Section 5 of the submitted paper presents the test results of these features. We will submit the complete FreeAuth prototype code along with a virtual machine image containing the correctly compiled binaries.

## Components

FreeAuth is primarily concerned with interactions between three parties (see Section 3.1 for more details)：

- **Prover(Client)**: Prover is the entity seeking to demonstrate ownership of a specific email address to the Verifier, and participates in email ownership authentication, commitment generation, and statement generation.
- **Verifier:** Verifier represents the applications or services interested in confirming the ownership of a Prover’s email address, and participates in email ownership authentication, commitment generation.
- **Server:** Server refers to any email service provider (e.g. Gmail, Outlook, etc.), and only participates in email ownership authentication. Meanwhile, Server does not need to make any changes for FreeAuth.

We categorize and demonstrate the functionality of FreeAuth into three parts: email ownership authentication, commitment generation, and statement generation:

- **Email Ownership Authentication:**  In this section, the Prover connects with the Verifier using TLS Oracle, followed by a connection with the Server for standard email authentication. The core functions are implemented in **TestFreeAuth/TestSMTP*.cpp**. Further details of the function can be found in Section 3.4.
- **Commitment Generation:**  In this section, Prover interacts with Verifier and generates a commitment to the data exchanged during the email ownership authentication process. The core functions are implemented in **TestFreeAuth/TestSingleCommit*.cpp**. Further details of the function can be found in Appendix F.1.
- **Statement Generation：**In this section, Prover independently selectively discloses information related to email addresses through non-interactive zero-knowledge proofs(ZKPs). The core functions are implemented in **TestFreeAuth/StatementGenaration**. Further details of the function can be found in Appendix F.2.

We provide a demo of a third-party email client to demonstrate our email ownership authentication process. The core functions are implemented in **TestFreeAuth/ApplicationDemo**

## Code Structure

**FreeAuth/:** This folder contains the implementation of FreeAuth's base functionality, including 2PC-AES-GCM and more. 

**TestFreeAuth/: **This folder contains the tests of FreeAuth's appliaction functionality, including three main parts of FreeAuth and an application demo. 

- **TestFreeAuth/TestSMTP*:** These files contain the implementation of email ownership authentication for Prover, Verifier and Server. A local presentation of the email ownership authentication functionality can be achieved by running these three files.
- **TestFreeAuth/TestSingleCommit*:** These files contain the implementation of commitment generation for Prover and Verifier. A local presentation of the commitment generation functionality can be achieved by running these two files. 
- **TestFreeAuth/StatementGeneration:** This folder contains zero-knowledge proof code for three statements generation based on [arkworks-rs](https://github.com/arkworks-rs/groth16.git). A local presentation of zero-knowledge proof generation for the three statements can be achieved by running these files.
- **TestFreeAuth/ApplicationDemo:** This folder contains the email client demo based on VUE3.js and Electron, integrated with FreeAuth's email ownership authentication.

**boringssl/:** This directory contains a tweaked version of  [BoringSSL](https://github.com/google/boringssl.git). BoringSSL is a fork of OpenSSL that is designed to meet Google's needs. DiStefano uses BoringSSL for TLS functionality, so we inherited it and made some more modifications for FreeAuth.

**Distefano/:**  This directory contains a tweaked version of [Distefano](https://github.com/brave-experiments/DiStefano.git). We primarily adopted the mechanism outlined by DiStefano to implement the TLS Oracle functions within FreeAuth.

**emp/:** This directory contains a tweaked version of emptool-kit(including [emp-ot](https://github.com/emp-toolkit/emp-ot.git), [emp-ag2pc](https://github.com/emp-toolkit/emp-ag2pc.git) and [emp-tool](https://github.com/emp-toolkit/emp-tool.git)). FreeAuth uses emp for all MPC functionality.

**2pc/:** This directory is a quick-access link to the Distefano/2pc/ folder and contains all the circuits and circuit generation files used in Distefano and FreeAuth.

## **Requirements**

**Recommended Environment:** Ubuntu 22.04, 4 cores, 16GB memory, 40GB Disk. 

**Minimum Requirements:**

- **Minimum Hardware Requirements**

  - Operating System: Ubuntu 18.04 or higher

  - Memory: 6GB or more

  - Disk Space: 2GB or more

- **Minimum Software Requirements**

  - CMake: Version ≥ 3.10

  - GNU Make: Version ≥ 4.1

  - GCC/G++: Version ≥ 9.4

  - Go (Golang): Version ≥ 1.10

  - Rustc: Version ≥ 1.65

  - Cargo: Version ≥ 1.65

## How to build

### Testing on **an** Artifact VM

We have completed the deployment and compilation of FreeAuth on a public Artifact VM provided by the committee, which you can access directly to run the compiled files. Since the committee does not allow the VM password to be made public, please refer to the comment on HotCRP for the connection details and password. After connecting to the Artifact VM, execute the following commands to run the test sample.

```
To connect use "ssh artifacts@acsac-x7e8-228-base.artifacts.measurement.network'
password: see HotCRP
cd freeauth
./run.sh
```

### Testing in a Docker container

The environment used for docker is Ubuntu 22.04, and it takes about 4 mins to build the image.

```
sudo snap install docker  #install docker
sudo docker build -t freeauth .  
sudo docker run -it freeauth    
```

**However, if you want to deploy  FreeAuth locally, please do the following.**

### Install dependencies

Please do not modify the apt commands, such as by adding the `--no-install-recommends` option.

```
sudo apt update
sudo apt -y install cmake make gcc g++ rustc cargo golang git libssl-dev time psmisc
```

### Building FreeAuth

We've combined the build commands into a single script **build.sh**.

Currently, you cannot use `git clone` to download because it is not supported by the anonymous repository we are using. Users need to manually download the zip from https://anonymous.4open.science/r/freeauth-543F, unzip it, and then execute the following commands.

```
cd freeauth
chmod +x build.sh run.sh
./build.sh
```

### Test and Benchmark

```
./run.sh
```

By running **run.sh**, we demonstrate email ownership authentication(Test 1), commitment generation(Test 2) and statement generation(Test 3) in turn. The test results in Section 5.1 for the submitted article are derived from the same program run in our experimental setup.

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

- Server

```
Test1: Email Ownership Authentication
========================================
==========Output from Server=============
[Server] simple server listen on:127.0.0.1:18388
[Server] Alternatively, you can run the client program by pasting the following command into another terminal:
./TestSMTPProver -a 127.0.0.1 -s 18388 -v VERIFIER_PORT
[Server] New client connect in: 127.0.0.1
[Server] Finished handshake with client 4 32
[Server] client 4 has down.
```

- Verifier

```
==========Output from Verifier=============
[Verifier] verifier listen on: 127.0.0.1:18389
[Verifier] Accepting
[Verifier] Doing handshake
[Verifier] Finished handshake
[Verifier] Preprocessing circuits
[Verifier] Preproc gcm share circuit... done
[Verifier] Preproc traffic circuit... done
[Verifier] Preproc HS1 circuit... done
[Verifier] Preproc all circuits cost 7.822756s
[Verifier] Reading key share
[Verifier] Creating key share
[Verifier] Writing key share
[Verifier] Reading server key share
[Verifier] Finishing 3PH
[Verifier] Writing HS_RECV
[Verifier] Doing ectf
[Verifier] Finished ectf
[Verifier] Doing HS derivation
[Verifier] Finished HS derivation
[Verifier] Reading SHTS_c and CHTS_c commit
[Verifier] Send SHTS_v and CHTS_v to Prover
[Verifier] Reading SHTS_c & CHTS_c and encrypted SC & SCV data
[Verifier] Reading H3 for SCV and H4 for SF verification
[Verifier] Verify [ServerCertificate,ServerCertificateVerify,ServerFinished]
[Verifier] Deriving TS
[Verifier] Deriving GCM shares
[Verifier] Calling into derivation circuit
[Verifier] Derived GCM shares
[Verifier] Enter attest()
[Verifier] Preproc aes gcm_tag gcm_cfy cost 4.460715s
[Verifier] Call aes_gcm_encrypt(), running 2PC process...
[Verifier] Run 2PC AES-GCM encrypt successful!
[Verifier] Call aes_gcm_encrypt(), running 2PC process...
[Verifier] Run 2PC AES-GCM encrypt successful!
[Verifier] Call aes_gcm_encrypt(), running 2PC process...
[Verifier] Run 2PC AES-GCM encrypt successful!
[Verifier] Call aes_gcm_encrypt(), running 2PC process...
```

- Prover

```
==========Output from Prover=============
[Prover] Connected to verifier
[Prover] Finished three party handshake
[Prover] Server connected. Now we begin send SMTP data packets
[Prover] Call 2PC aes_encrypt with 15 bytes, seq = 0
[Prover] Run 2PC aes_encrypt successful, now send the packet to Server
Send -> HELO emailreg
[Prover] Call 2PC aes_encrypt with 12 bytes, seq = 1
[Prover] Run 2PC aes_encrypt successful, now send the packet to Server
Send -> AUTH LOGIN
[Prover] Call 2PC aes_encrypt with 22 bytes, seq = 2
[Prover] Run 2PC aes_encrypt successful, now send the packet to Server
Send -> dXNlcm5hbWVAcXEuY29t
[Prover] Call 2PC aes_encrypt with 22 bytes, seq = 3
[Prover] Run 2PC aes_encrypt successful, now send the packet to Server
Send -> eW91cl9wYXNzd29yZA==
```

Test results are shown:

This part of the result indicates that during the email ownership authentication process, the time for preparing the circuits of TLS Oracle is  7.85s,  the time for completing the three-party handshake is 1.36s, the time for preparing the AES-GCM circuits which are uesd to encrypt the PLAIN authentication messages sent by Prover is 4.50s, and the time for completing the PLAIN authentication is 0.35s,  with a total time is 14.0s. 

```
==============Time data print==============
Preproc all handshake circuits before connect to server time costs: 7.857054
Three party handshake total time costs: 1.363712
Preproc AES-GCM-128 circuits time costs: 4.460449
Run threeparty SMTP auth proccess time costs: 0.351344
Total time costs: 14.032559
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

This part of the result indicates that the time for commiting the single block is 2.70s.

```
Test2: Commitment Generation
========================================
Commit time costs: 2.703217
```

**Test3: Statement Generation**

We implemented this part using Rust. Prover use commitment to generate three statements related to specific email address. The test implements statement generation and validation, and outputs the time at which the statements were generated.

Specific running commands:

```
cd build
./release/email 
```

Specific test output:

This part of result indicates that the time for  Prover to generate three kinds of statements is 1.24s,  2.50s, and 1.15s respectively. The time difference of these three kinds of statements is mainly caused by the number of times the SHA256 algorithm is used and the length of the content which is inputed to the SHA256 algorithm.

```
Test3: Statement Generation
========================================
Statement Example 1: Authentication of email domainsAuthentication of email domains
Creating parameters...
Creating proofs...
1.24996383 seconds
Statement Example 2: Authentication of email addresses and generation of identifiers
Creating parameters...
Creating proofs...
2.5040538249999997 seconds
Statement Example 3: Authentication of email address
Creating parameters...
Creating proofs...
1.1486866629999999 seconds
```



## GUI Application Demo

We provide a demo of a third-party email client to demonstrate our email ownership authentication process. Provide users with visualized email ownership authentication services.

We provide support for PLAIN, LOGIN and Google OAuth2 authentication methods in this demo, you can enter the relevant information for actual testing. Please note that this demo only supports TLS link based on TLSv1.3 implementation at present, please make sure that the email server you try can provide TLSv1.3 service. Meanwhile, since the Google OAuth2 service we use is a beta service, only the email address that are added in the test list can get the OAuth2 authentication service. Since this is a blind review phase, we recommend using email addresses that do not require OAuth2 authentication for experimental testing.

### How to build

```
sudo apt update
sudo apt install nodejs
```

### **How to run**

```
cd TestFreeAuth/ApplicationDemo
npm install
npm run serve  # build project & run
```



