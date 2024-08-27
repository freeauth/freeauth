#include <emp-tool/emp-tool.h>
#include <emp-tool/utils/constants.h>
#include "test/single_execution.h"
using namespace std;
using namespace emp;


int main(int argc, char** argv) {
	int party, port;
	parse_party_and_port(argv, &party, &port);
	NetIO* io = new NetIO(party==ALICE ? nullptr:IP, port);
//	io->set_nodelay();
	string circuit_file_location="/home/fyj/Downloads/Email-Email/2pc/key-derivation/derive_commitments_sha256_128.txt";
    // NIST test vector
	std::string input_message_key;
	std::cout << "message: ";
	std::cin >> input_message_key;
    // string input_message_key = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010";
	string expected_output = "69C4E0D86A7B0430D8CDB78070B4C55A";	
	cout<<input_message_key<<endl;
	test<NetIO>(party, io, circuit_file_location,  expected_output,input_message_key);
    // cout << "expected output: " << endl << hex_to_binary(expected_output) << endl;
	delete io;
	return 0;
}
