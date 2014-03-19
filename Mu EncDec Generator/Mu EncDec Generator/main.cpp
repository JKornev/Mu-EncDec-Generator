#include <stdio.h>
#include <iostream>
#include <fstream>
#include <Windows.h>
#include <set>
#include <ctime>
#include <string>
#include <cmath>
#include "Encrypt.h"

using namespace std;

unsigned int load_key[4] = {0x3F08A79B, 0xE25CC287, 0x93D27AB9, 0x20DEA7BF};

unsigned int mod_key[4] = {}, 
	xor_key[4] = {}, 
	enc_key[4] = {}, 
	dec_key[4] = {};

bool generate_keys(const char *enc_path, const char *dec_path)
{
	set<unsigned int> mod_mult;
	fstream file;
	char head[6] = {0x12, 0x11, 0x36, 0, 0, 0};

	for (unsigned int i = 0; i < 4; i++) {
		xor_key[i] = (rand() % 0xFFFF) + 1;
		mod_key[i] = ((unsigned int)rand() % 0xFFFF) + 0x10000;
	}

	//enc key generation
	for (unsigned int i = 0; i < 4; i++) {
		unsigned int val = mod_key[i];

		mod_mult.clear();//prime modulus multipliers
		for (unsigned int a = 2; a <= mod_key[i]; a++) {
			if (val % a == 0) {
				val /= a;
				mod_mult.insert(a);
				a = 1;
			}
		}

		while (true) {//coprime integer generation
			bool found = false;
			val = enc_key[i] = ((rand() % mod_key[i]) % 0xFFFE) + 2;

			for (unsigned int a = 2; a <= enc_key[i]; a++) {
				if (val % a == 0) {
					if (mod_mult.find(a) != mod_mult.end()) {
						found = true;
						break;
					}
					val /= a;
					a = 1;
				}
			}
			if (found) {
				continue;
			}

			break;
		}
	}

	//dec generation
	for (int i = 0; i < 4; i++) {
		bool found = false;

		for (int a = 0; a < mod_key[i]; a++) {
			if ((enc_key[i] * a) % mod_key[i] == 1) {
				//printf("%d %x\n", i, a);
				dec_key[i] = a;
				found = true;
				break;
			}
		}
		if (!found) {
			cout << "Error, generation failed" << endl;
			return false;
		}
	}

/*
	cout << "Keys pair generated:" << endl;
	cout << "mod " << hex << mod_key[0] << " " << mod_key[1] << " " << mod_key[2] << " " << mod_key[3] << endl;
	cout << "xor " << hex << xor_key[0] << " " << xor_key[1] << " " << xor_key[2] << " " << xor_key[3] << endl;
	cout << "enc " << hex << enc_key[0] << " " << enc_key[1] << " " << enc_key[2] << " " << enc_key[3] << endl;
	cout << "dec " << hex << dec_key[0] << " " << dec_key[1] << " " << dec_key[2] << " " << dec_key[3] << endl;*/

	//xor keyset
	for (int i = 0; i < 4; i++) {
		mod_key[i] ^= load_key[i];
		enc_key[i] ^= load_key[i];
		dec_key[i] ^= load_key[i];
		xor_key[i] ^= load_key[i];
	}

	file.open(enc_path, fstream::out | fstream::binary);

	file.write(head, 6);
	file.write((char *)mod_key, 16);
	file.write((char *)enc_key, 16);
	file.write((char *)xor_key, 16);

	file.close();

	file.open(dec_path, fstream::out | fstream::binary);

	file.write(head, 6);
	file.write((char *)mod_key, 16);
	file.write((char *)dec_key, 16);
	file.write((char *)xor_key, 16);

	file.close();

	return true;
}

bool test_keys(char *enc_path, char *dec_path)
{
	CSimpleModulus enc, dec;
	char buf[20000] = {};
	char enc_buf[30000], dec_buf[30000];
	int res;

	for (int i = 0; i < sizeof(buf); i++) {
		buf[i] = rand() % 0xFF;
	}

	if (!enc.LoadEncryptionKey(enc_path)) {
		cout << "Can't load enc key!" << endl;
		return false;
	}

	if (!dec.LoadDecryptionKey(dec_path)) {
		cout << "Can't load enc key!" << endl;
		return false;
	}

	res = enc.Encrypt(enc_buf, buf, sizeof(buf));
	if (res == -1) {
		//cout << "Encryption error!" << endl;
		return false;
	}

	res = dec.Decrypt(dec_buf, enc_buf, res);
	if (res == -1) {
		//cout << "Decryption error!" << endl;
		return false;
	}

	for (int i = 0; i < sizeof(buf); i++) {
		if (buf[i] != dec_buf[i]) {
			return false;
		}
	}
	
	return true;
}

int main()
{
	char enc_path[20], dec_path[20];

	cout << "==============================================" << endl
		 << " Welcome to MuEncDec Key Generator by JKornev" << endl
		 << "         http://armored.pro <c> 2014" << endl
		 << "xakumm - noob and lamer, he tried to sell keys" << endl
		 << "==============================================" << endl;

	srand(time(NULL));

	for (int i = 1; i < 101; ) {
		sprintf_s(enc_path, "enc%d.dat", i);
		sprintf_s(dec_path, "dec%d.dat", i);
		if (!generate_keys(enc_path, dec_path)) {
			continue;
		}

		if (!test_keys(enc_path, dec_path)) {
			continue;
		}

		cout << "Key #" << i << " created" << endl;
		i++;
	}

	return 0;
}
