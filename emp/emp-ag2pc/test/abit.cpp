#include <emp-tool/emp-tool.h>
#include "emp-ag2pc/leaky_deltaot.h"
#include<thread>
using namespace std;
using namespace emp;

int sizee = 1<<20;

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);

	PRG prg;
	NetIO * io = new NetIO(party==ALICE ? nullptr:"127.0.0.1", port);
	LeakyDeltaOT<NetIO> *abit = new LeakyDeltaOT<NetIO>(io);
	bool delta[128];
	block * t1 = new block[sizee];
	prg.random_bool(delta, 128);
	delta[0] = true;

	if(party == ALICE)
		abit->setup_send(delta);
	else abit->setup_recv();
	auto tt1 = clock_start();
	if(party == ALICE) {
		abit->send_dot(t1, sizee);
	} else {
		abit->recv_dot(t1, sizee);
	}
	cout << time_from(tt1)<<endl;

	block Delta, tmp;
	if (party == ALICE) {
		io->send_block(&(abit->Delta), 1);
		io->send_block(t1, sizee);
	} else {
		io->recv_block (&Delta, 1);
		for(int i = 0; i < sizee; ++i) {
			io->recv_block (&tmp, 1);
			if(getLSB(t1[i]))
				tmp = tmp ^ Delta;
			if(memcmp(&t1[i], &tmp, 16)!=0)
				error("check failed!");
		}
	}
	delete abit;
	delete io;
	return 0;
}
