#include <emp-tool/emp-tool.h>
#include "test/single_execution.h"
using namespace std;
using namespace emp;

int main(int argc, char** argv) {
	int party, port;
	parse_party_and_port(argv, &party, &port);
	NetIO* io = new NetIO(party==ALICE ? nullptr:IP, port);
//	io->set_nodelay();
	std::string input;
	if(party==ALICE) {
		input = "00000000000000000000000000000001" 
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" 
				"00000000000000000000000000000000"
				"00000000000000000000000000000001" 
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				"00000000000000000000000000000000";
	} else {
		input = "10000000000000000000000000000000"
				"55555555555555555555555555555555"
				"00000000000000000000000000000000"
				"10000000000000000000000000000000"
				"55555555555555555555555555555555"
				"00000000000000000000000000000000";
	}
	test<NetIO>(party, io, argv[3],"",input);
	delete io;
	return 0;
}
