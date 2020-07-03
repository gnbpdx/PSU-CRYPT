#include "block.h"
#include "key.h"
#include <stdlib.h>
#include <string.h>
#define BUFFER_SIZE 512
#include "globals.h"
//Feistel Network for encryption
struct block feistel_encrypt(struct block* text, struct key* keyobj)
{
	int ROUNDS = 3*KEY_SIZE/12;
	keyobj->set_mode(keyobj, 'e');
	int round = 0;
	struct block new_text = *text;
	if (PRINT_ROUNDS)
		printf("Encryption:\n");
	while(round < ROUNDS)
	{

		struct subblock temp;
		temp.R0 = new_text.R0;
		temp.R1 = new_text.R1;
		if (PRINT_ROUNDS)
		{
			printf("Beginning of Round: %d\n", round);	
			PRINT_SUBKEYS = true;
			PRINT_ROUNDS = false;
			printf("Keys: ");
			F(&temp, round, keyobj);
			PRINT_SUBKEYS = false;
			keyobj->set_mode(keyobj, 'd');
			F(&temp, round, keyobj);
			keyobj->set_mode(keyobj, 'e');
			PRINT_ROUNDS = true;
		}
		temp = F(&temp, round, keyobj);
		unsigned int R0 = new_text.R2 ^ temp.R0;
		unsigned int R1 = new_text.R3 ^ temp.R1;
		new_text.R2 = new_text.R0;
		new_text.R3 = new_text.R1;
		new_text.R0 = R0;
		new_text.R1 = R1;
		if (PRINT_ROUNDS)
		{
			printf("Block: 0x%x%x%x%x\nEnd of Round: %d\n\n", \
			new_text.R0, new_text.R1, new_text.R2, new_text.R3, round);
		}
		++round;
	}
	unsigned int temp1 = new_text.R0;
	unsigned int temp2 = new_text.R1;
	new_text.R0 = new_text.R2;
	new_text.R1 = new_text.R3;
	new_text.R2 = temp1;
	new_text.R3 = temp2;
	
	
	return new_text;
		
}
//Feistel Network for Decryption
struct block feistel_decrypt(struct block* text, struct key* keyobj)
{

	int ROUNDS = 3*KEY_SIZE/12;
	keyobj->set_mode(keyobj, 'd');
	int round = ROUNDS - 1;
	struct block new_text = *text;


	unsigned int temp1 = new_text.R0;
	unsigned int temp2 = new_text.R1;
	new_text.R0 = new_text.R2;
	new_text.R1 = new_text.R3;
	new_text.R2 = temp1;
	new_text.R3 = temp2;
 	
	if (PRINT_ROUNDS)
		printf("Decryption:\n");
	while(round >= 0)
	{

		if (PRINT_ROUNDS)
		{
			printf("Beginning of Round: %d\n", round);	
		}
		struct subblock temp;
		temp.R0 = new_text.R2;
		temp.R1 = new_text.R3;
		temp = F(&temp, round, keyobj);
		unsigned int R2 = new_text.R0 ^ temp.R0;
		unsigned int R3 = new_text.R1 ^ temp.R1;
		new_text.R0 = new_text.R2;
		new_text.R1 = new_text.R3;
		new_text.R2 = R2;
		new_text.R3 = R3;

		if (PRINT_ROUNDS)
		{
			printf("Block: 0x%x%x%x%x\nEnd of Round: %d\n\n", \
			new_text.R0, new_text.R1, new_text.R2, new_text.R3, round);
		}
		--round;
	}
	return new_text;

}
//Reads in a stream of plaintext into an array of blocks
struct text* read_in_characters(FILE* FP)
{
	if (!FP)
		return NULL;
	long count = 0;
	char character;
	char buffer[9];
	for (int i = 0; i < 9; ++i)
	{
		buffer[i] = '\0';
	}
	struct text* new_text = malloc(sizeof(struct text));
	new_text->block_array = NULL;
	while(fgets(buffer, 9, FP) > 0)
	{
		if (strlen(buffer) < 8)
		{
			while(fgets(buffer + strlen(buffer), 9 - strlen(buffer), FP) > 0 && strlen(buffer) < 8)
			{
			}
			if (strlen(buffer) < 8)
				break;		
		}
		struct block* new_block = malloc(sizeof(struct block));
		++count;
		new_block->R0 = (buffer[0] << 8) + buffer[1];
		new_block->R1 = (buffer[2] << 8) + buffer[3];
		new_block->R2 = (buffer[4] << 8) + buffer[5];
		new_block->R3 = (buffer[6] << 8) + buffer[7];
		new_text->block_array = realloc(new_text->block_array, count*sizeof(struct text));
		new_text->block_array[count - 1] = *new_block;
		free(new_block);
		for (int i = 0; i < 9; ++i)
			buffer[i] = '\0';
		
	}
	struct block* new_block = malloc(sizeof(struct block));
	++count;
	new_text->block_array = realloc(new_text->block_array, count*sizeof(struct text));
	new_block->R0 = (buffer[0] << 8) + buffer[1];
	new_block->R1 = (buffer[2] << 8) + buffer[3];
	new_block->R2 = (buffer[4] << 8) + buffer[5];
	new_block->R3 = (buffer[6] << 8) | (8 - strlen(buffer));
	new_text->block_array[count - 1] = *new_block;
	new_text->NUM_OF_BLOCKS = count;
	free(new_block);
	return new_text;
}
//Used to read in ciphertext.
// Assumes ciphertext is formatted properly
struct text* read_in_hex(FILE* FP)
{
	if (!FP)
		return NULL;
	long count = 0;
	char character;
	char buffer[17];
	fgets(buffer, 3, FP);
	if (strcmp(buffer, "0x") && strcmp(buffer, "0X"))
		return NULL;
	for (int i = 0; i < 17; ++i) //fill buffer with 0
	{
		buffer[i] = '\0';
	}
	struct text* new_text = malloc(sizeof(struct text));
	new_text->block_array = NULL;
	while(fgets(buffer, 17 , FP) && strlen(buffer) == 16)
	{
		struct block* new_block = malloc(sizeof(struct block));
		++count;
		char temp = buffer[4];
		unsigned int temp2;
		buffer[4] = '\0';
		sscanf(buffer, "%x", &temp2);
		new_block->R0 = temp2;
		buffer[4] = temp;
		temp = buffer[8];
		buffer[8] = '\0';
		sscanf(buffer + 4, "%x", &temp2);
		new_block->R1 = temp2;
		buffer[8] = temp;
		temp = buffer[12];
		buffer[12] = '\0';
		sscanf(buffer + 8, "%x", &temp2);
		new_block->R2 = temp2;

		buffer[12] = temp;
		sscanf(buffer + 12, "%x", &temp2);
		new_block->R3 = temp2;	
		new_text->block_array = realloc(new_text->block_array, count*sizeof(struct text));
		new_text->block_array[count - 1] = *new_block;
		free(new_block);
		for (int i = 0; i < 17; ++i)
			buffer[i] = '\0';
		
	}

	new_text->NUM_OF_BLOCKS = count;
	return new_text;
}
//prints out decrypted plaintext
void print_characters(struct text* textobj, FILE* FP)
{
	char buffer[8];
	buffer[8] = '\0';
	for (long i = 0; i < textobj->NUM_OF_BLOCKS - 1; ++i)
	{
		buffer[0] = textobj->block_array[i].R0 >> 8;
		buffer[1] = textobj->block_array[i].R0 & 0xFF;
		buffer[2] = textobj->block_array[i].R1 >> 8;
		buffer[3] = textobj->block_array[i].R1 & 0xFF;
		buffer[4] = textobj->block_array[i].R2 >> 8;
		buffer[5] = textobj->block_array[i].R2 & 0xFF;
		buffer[6] = textobj->block_array[i].R3 >> 8;
		buffer[7] = textobj->block_array[i].R3 & 0xFF;
		fprintf(FP, "%s", buffer);

	}
	long i = textobj->NUM_OF_BLOCKS - 1;
	buffer[0] = textobj->block_array[i].R0 >> 8;
	buffer[1] = textobj->block_array[i].R0 & 0xFF;
	buffer[2] = textobj->block_array[i].R1 >> 8;
	buffer[3] = textobj->block_array[i].R1 & 0xFF;
	buffer[4] = textobj->block_array[i].R2 >> 8;
	buffer[5] = textobj->block_array[i].R2 & 0xFF;
	buffer[6] = textobj->block_array[i].R3 >> 8;
	buffer[7] = textobj->block_array[i].R3 & 0xFF;
	int padding = buffer[7] & 0xF;
	buffer[8 - padding] = '\0';
	fprintf(FP, "%s", buffer);
}
//Prints array of blocks to designated file pointer in hex
void print_hex(struct text* textobj, FILE* FP)
{
	fprintf(FP, "0x");
	for (long i = 0; i < textobj->NUM_OF_BLOCKS; ++i)
	{
		unsigned int hex1 = textobj->block_array[i].R0;	
		unsigned int hex2 = textobj->block_array[i].R1;
		unsigned int hex3 = textobj->block_array[i].R2;
		unsigned int hex4 = textobj->block_array[i].R3;
		fprintf(FP, "%04x%04x%04x%04x", hex1, hex2, hex3, hex4);

	}
}
struct block* read_IV(FILE* FP) //read initialization vector from file
{

	if (!FP)
		return NULL;
	char buffer[BUFFER_SIZE];
	fscanf(FP, "%512s", buffer);
	if (strlen(buffer) != 18)
		return NULL;
	char temp[7];
	temp[4] = '\0';
	unsigned int temp2;
	int i = 0;
	temp[0] = buffer[0];
	temp[1] = buffer[1];
	if (temp[0] != '0' || (temp[1] != 'X' && temp[1] != 'x'))
		return NULL;
	struct block* blockobj = malloc(sizeof(struct block));
	for (int i = 2; i < 6; ++i)
	{
		temp[i] = buffer[i];
		sscanf(temp, "%x", &temp2);
		blockobj->R0 = temp2;
	}
	for (int i = 6; i < 10; ++i)
	{
		temp[i-4] = buffer[i];
		sscanf(temp, "%x", &temp2);
		blockobj->R1 = temp2;
	}
	for (int i = 10; i < 14; ++i)
	{
		temp[i-8] = buffer[i];
		sscanf(temp, "%x", &temp2);
		blockobj->R2 = temp2;
	}
	for (int i = 14; i < 18; ++i)
	{
		temp[i-12] = buffer[i];
		sscanf(temp, "%x", &temp2);
		blockobj->R3 = temp2;
	}
	return blockobj;
}
