#include "key.h"
#include <string.h>
#define BUFFER_SIZE 512
#include "globals.h"
//input key from file
int input_key(struct key* keyobj, FILE* FP)
{
	if (!FP)
		return -1;
	char buffer[BUFFER_SIZE];
	fscanf(FP, "%512s", buffer);
	if (strlen(buffer) != (2 + 2*KEY_BYTES))
		return -1;
	char temp[5];
	temp[4] = '\0';
	unsigned int temp2;
	int i = 0;
	temp[0] = buffer[0];
	temp[1] = buffer[1];
	if (temp[0] != '0' || (temp[1] != 'X' && temp[1] != 'x'))
		return -1;
	for (int i = 0; i < KEY_BYTES; ++i)
	{

		temp[2] = buffer[2*i+2];
		temp[3] = buffer[2*i+3];
		sscanf(temp, "%x", &temp2);
		keyobj->key_byte[(KEY_BYTES -1)-i] = temp2;
	}
	return 0;
}
//key rotation for encryption
void encryption_rotate(struct key* this) //left rotate
{
	unsigned int temp;

	temp = (0x80 & this->key_byte[KEY_BYTES - 1]) >> 7;
	for (int i = KEY_BYTES - 1; i > 0; --i)
	{	
		this->key_byte[i] <<= 1;
		this->key_byte[i] |= ((this->key_byte[i-1] & 0x80) >> 7);
	}
	this->key_byte[0] <<= 1;
	this->key_byte[0] |= temp;
	
	
}
//key rotation for decryption
void decryption_rotate(struct key* this)
{
	unsigned int temp, temp2;
	temp = (1 & this->key_byte[0]) << 7;
	for (int i = 0; i < KEY_BYTES - 1; ++ i)
	{
		this->key_byte[i] >>= 1;
		this->key_byte[i] |= ((1 & this->key_byte[i+1]) << 7);
	}
	this->key_byte[KEY_BYTES - 1] >>= 1;
	this->key_byte[KEY_BYTES - 1] |= temp;
}
unsigned char encryption_K(struct key* this, unsigned int num)
{
	this->rotate(this);
	num %= KEY_BYTES;
	return this->key_byte[num];
}
unsigned char decryption_K(struct key* this, unsigned int num)
{
	num %= KEY_BYTES;
	unsigned char rval = this->key_byte[num];
	this->rotate(this);	
	return rval;
}
//assigns functions in key struct depending on whether mode is encryption or decryption
int set_mode(struct key* this, char mode)
{
	switch (mode)
	{
		case 'e':
			this->rotate = encryption_rotate;
			this->K = encryption_K;
			this->input_key = input_key;
			break;
		case 'd':
			this->rotate = decryption_rotate;
			this->K = decryption_K;
			this->input_key = input_key;
			break;
		default:
			return -1;
			
	}
	return 0;	
		
}

