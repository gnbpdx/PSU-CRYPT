#include "block.h"
#include "key.h"
#include "globals.h"
unsigned int ftable[] = 
{0xa3,0xd7,0x09,0x83,0xf8,0x48,0xf6,0xf4,0xb3, 0x21,0x15,0x78,0x99,0xb1,0xaf,0xf9,
0xe7,0x2d,0x4d,0x8a,0xce,0x4c,0xca,0x2e,0x52,0x95,0xd9,0x1e,0x4e,0x38,0x44,0x28,
0x0a,0xdf,0x02,0xa0,0x17,0xf1,0x60,0x68,0x12,0xb7,0x7a,0xc3,0xe9,0xfa,0x3d,0x53,
0x96,0x84,0x6b,0xba,0xf2,0x63,0x9a,0x19,0x7c,0xae,0xe5,0xf5,0xf7,0x16,0x6a,0xa2,
0x39,0xb6,0x7b,0x0f,0xc1,0x93,0x81,0x1b,0xee,0xb4,0x1a,0xea,0xd0,0x91,0x2f,0xb8,
0x55,0xb9,0xda,0x85,0x3f,0x41,0xbf,0xe0,0x5a,0x58,0x80,0x5f,0x66,0x0b,0xd8,0x90,
0x35,0xd5,0xc0,0xa7,0x33,0x06,0x65,0x69,0x45,0x00,0x94,0x56,0x6d,0x98,0x9b,0x76,
0x97,0xfc,0xb2,0xc2,0xb0,0xfe,0xdb,0x20,0xe1,0xeb,0xd6,0xe4,0xdd,0x47,0x4a,0x1d,
0x42,0xed,0x9e,0x6e,0x49,0x3c,0xcd,0x43,0x27,0xd2,0x07,0xd4,0xde,0xc7,0x67,0x18,
0x89,0xcb,0x30,0x1f,0x8d,0xc6,0x8f,0xaa,0xc8,0x74,0xdc,0xc9,0x5d,0x5c,0x31,0xa4,
0x70,0x88,0x61,0x2c,0x9f,0x0d,0x2b,0x87,0x50,0x82,0x54,0x64,0x26,0x7d,0x03,0x40,
0x34,0x4b,0x1c,0x73,0xd1,0xc4,0xfd,0x3b,0xcc,0xfb,0x7f,0xab,0xe6,0x3e,0x5b,0xa5,
0xad,0x04,0x23,0x9c,0x14,0x51,0x22,0xf0,0x29,0x79,0x71,0x7e,0xff,0x8c,0x0e,0xe2,
0x0c,0xef,0xbc,0x72,0x75,0x6f,0x37,0xa1,0xec,0xd3,0x8e,0x62,0x8b,0x86,0x10,0xe8,
0x08,0x77,0x11,0xbe,0x92,0x4f,0x24,0xc5,0x32,0x36,0x9d,0xcf,0xf3,0xa6,0xbb,0xac,
0x5e,0x6c,0xa9,0x13,0x57,0x25,0xb5,0xe3,0xbd,0xa8,0x3a,0x01,0x05,0x59,0x2a,0x46};
//returns correct table entry from input
unsigned int Ftable(unsigned int input)
{
	unsigned int row = (0xF0 & input) >> 4;
	unsigned int col = 0x0F & input;
	return ftable[row*16 + col];
}
//G function
struct G_block G(struct G_block* this, unsigned int round, struct key* keyobj)
{
	unsigned char key3, key4, key5, key6;
	if (keyobj->rotate == encryption_rotate) //encryption mode
	{
		key3 = keyobj->K(keyobj, 4*round);
		key4 = keyobj->K(keyobj, 4*round+1);
		key5 = keyobj->K(keyobj, 4*round+2);
		key6 = keyobj->K(keyobj, 4*round+3);
		if (PRINT_SUBKEYS)
		{
			unsigned int KEY3 = key3;
			unsigned int KEY4 = key4;
			unsigned int KEY5 = key5;
			unsigned int KEY6 = key6;
		printf("0x%x 0x%x 0x%x 0x%x ", KEY3, KEY4, KEY5, KEY6);	
		}
	}
	else //decryption mode
	{

		key6 = keyobj->K(keyobj, 4*round+3);
		key5 = keyobj->K(keyobj, 4*round+2);
		key4 = keyobj->K(keyobj, 4*round+1);
		key3 = keyobj->K(keyobj, 4*round);
	}
	unsigned int g3 = Ftable(this->g2 ^ key3) ^ this->g1;
	unsigned int g4 = Ftable(g3 ^ key4) ^ this->g2;
	unsigned int g5 = Ftable(g4 ^ key5) ^ g3;
	unsigned int g6 = Ftable(g5 ^ key6) ^g4;
	struct G_block val;
	val.g1 = g5;
	val.g2 = g6;
	if (PRINT_ROUNDS)
	{
		printf("g1: 0x%x g2: 0x%x g3: 0x%x g4: 0x%x g5: 0x%x g6: 0x%x\n", \
		this->g1, this->g2, g3, g4, g5, g6);
	}
	return val;
}
//F function for Feistel Network
struct subblock F(struct subblock* this, unsigned int round, struct key* keyobj)
{
	struct G_block T0, T1;
	unsigned char key0, key1, key2, key3;
	if (keyobj->rotate == encryption_rotate) //encryption mode
	{

		struct G_block temp;
		temp.g1 = (this->R0 & 0xFF00) >> 8;
		temp.g2 = this->R0 & 0x00FF;
		T0 = G(&temp, round, keyobj);
		temp.g1 = (this->R1 & 0xFF00) >> 8;
		temp.g2 = this->R1 & 0x00FF;
		T1 = G(&temp, round, keyobj);
		key0 = keyobj->K(keyobj, 4*round);
		key1 = keyobj->K(keyobj, 4*round+1);
		key2 = keyobj->K(keyobj, 4*round+2);
		key3 = keyobj->K(keyobj, 4*round+3);
	

		if(PRINT_SUBKEYS)
		{
			unsigned int KEY0 = key0;
			unsigned int KEY1 = key1;
			unsigned int KEY2 = key2;
			unsigned int KEY3 = key3;
			printf("0x%x 0x%x 0x%x 0x%x\n", KEY0, KEY1, KEY2, KEY3);	
		}

	}	
	else //decryption mode
	{
		struct G_block temp;
		key3 = keyobj->K(keyobj, 4*round+3);
		key2 = keyobj->K(keyobj, 4*round+2);
		key1 = keyobj->K(keyobj, 4*round+1);
		key0 = keyobj->K(keyobj, 4*round);
		temp.g1 = (this->R1 & 0xFF00) >> 8;
		temp.g2 = this->R1 & 0x00FF;
		T1 = G(&temp, round, keyobj);
		temp.g1 = (this->R0 & 0xFF00) >> 8;
		temp.g2 = this->R0 & 0x00FF;
		T0 = G(&temp, round, keyobj);
		
	}


	struct subblock val;
	val.R0 = (key0 << 8) + key1;
	val.R0 += (((T0.g1 << 8) + T0.g2)+ 2*((T1.g1 << 8) + T1.g2));
	val.R1 = (key2 << 8) + key3;
	val.R1 += (2*((T0.g1 << 8) + T0.g2) + ((T1.g1 << 8) + T1.g2));
	if (PRINT_ROUNDS)
	{
		printf("t0: 0x%x%x t1: 0x%x%x\n", T0.g1, T0.g2, T1.g1, T1.g2);
		printf("f0: 0x%x f1: 0x%x\n", val.R0, val.R1);
	}
	return val;
}
//Whitens block with key
struct block whiten(struct block* text, struct key* keyobj)
{
	unsigned int keys[4];
	for (int i = 0; i < 4; ++i)
	{
		keys[i] = (keyobj->key_byte[(KEY_BYTES - 1)-2*i] << 8) + keyobj->key_byte[(KEY_BYTES - 1)-(2*i+1)];
	}	
	struct block rval;
	rval.R0 = text->R0 ^ keys[0];
	rval.R1 = text->R1 ^ keys[1];
	rval.R2 = text->R2 ^ keys[2];
	rval.R3 = text->R3 ^ keys[3];
	return rval;
}
//performs xor with 2 blocks
struct block XOR(struct block* text1, struct block* text2)
{
	struct block xor;
	xor.R0 = text1->R0 ^ text2->R0;
	xor.R1 = text1->R1 ^ text2->R1;
	xor.R2 = text1->R2 ^ text2->R2;
	xor.R3 = text1->R3 ^ text2->R3;
	return xor;	
}