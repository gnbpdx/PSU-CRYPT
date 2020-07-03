#include <unistd.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "key.h"
#include "block.h"
#include "globals.h"
bool PRINT_SUBKEYS;
bool PRINT_ROUNDS;
int KEY_SIZE;
int KEY_BYTES;


struct block (*cipher)(struct block*, struct key*);
//Electronic Code Book Mode
//Initialization Vector is not used
//Decryption runs the same, but using the inverse feistel cipher
struct text* ECB_MODE(struct text* textobj, struct block* IV, struct key* keyobj)
{
	struct text* new_text = malloc(sizeof(struct text));
	new_text->block_array = malloc(sizeof(struct block) * textobj->NUM_OF_BLOCKS);
	new_text->NUM_OF_BLOCKS = textobj->NUM_OF_BLOCKS;
	for (long i = 0; i < textobj->NUM_OF_BLOCKS; ++i)
	{
		new_text->block_array[i] = whiten(textobj->block_array + i, keyobj);
		new_text->block_array[i] = cipher(new_text->block_array + i, keyobj);	
		new_text->block_array[i] = whiten(new_text->block_array + i, keyobj);
	}
	return new_text;
		
}
//Cipher Block Chaining Mode
struct text* CBC_encrypt_MODE(struct text* textobj, struct block* IV, struct key* keyobj)
{
	
	struct text* new_text = malloc(sizeof(struct text));
	new_text->block_array = malloc(sizeof(struct block) * textobj->NUM_OF_BLOCKS);
	new_text->NUM_OF_BLOCKS = textobj->NUM_OF_BLOCKS;
	if (new_text->NUM_OF_BLOCKS > 0)
	{
		new_text->block_array[0] = XOR(IV, textobj->block_array);
		new_text->block_array[0] = cipher(new_text->block_array, keyobj);	
	}
	for (long i = 1; i < textobj->NUM_OF_BLOCKS; ++i)
	{
		new_text->block_array[i] = XOR(new_text->block_array + (i - 1), textobj->block_array + i);
		new_text->block_array[i] = cipher(new_text->block_array + i, keyobj);
	}	
	return new_text;
}
struct text* CBC_decrypt_MODE(struct text* textobj, struct block* IV, struct key* keyobj)
{
	
	struct text* new_text = malloc(sizeof(struct text));
	new_text->block_array = malloc(sizeof(struct block) * textobj->NUM_OF_BLOCKS);
	new_text->NUM_OF_BLOCKS = textobj->NUM_OF_BLOCKS; 
	if (new_text->NUM_OF_BLOCKS > 0)
	{
		new_text->block_array[0] = cipher(textobj->block_array, keyobj);
		new_text->block_array[0] = XOR(new_text->block_array, IV);
	}
	for (long i = 1; i < textobj->NUM_OF_BLOCKS; ++i)
	{
		new_text->block_array[i] = cipher(textobj->block_array + i, keyobj);
		new_text->block_array[i] = XOR(new_text->block_array + i, textobj->block_array + (i-1));
		
	}
	return new_text;
} 
//Output Feedback Mode
//Decryption runs the same (no inverse cipher)
struct text* OFB_MODE(struct text* textobj, struct block* IV, struct key* keyobj)
{
	
	struct text* new_text = malloc(sizeof(struct text));
	new_text->block_array = malloc(sizeof(struct block) * textobj->NUM_OF_BLOCKS);
	new_text->NUM_OF_BLOCKS = textobj->NUM_OF_BLOCKS;
	struct block* IV_block = malloc(sizeof(struct block) * textobj->NUM_OF_BLOCKS);
	if (textobj->NUM_OF_BLOCKS > 0)
		IV_block[0] = cipher(IV, keyobj);
	for (long i = 1; i < textobj->NUM_OF_BLOCKS; ++i)
	{
		IV_block[i] = cipher(IV_block + (i-1), keyobj);
	}
	for (long i = 0; i < textobj->NUM_OF_BLOCKS; ++i)
	{
		new_text->block_array[i] = XOR(IV, textobj->block_array + i);
	}
	return new_text;
}
//Cipher Feedback Mode
struct text* CFB_encrypt_MODE(struct text* textobj, struct block* IV, struct key* keyobj)
{

	struct text* new_text = malloc(sizeof(struct text));
	new_text->block_array = malloc(sizeof(struct block) * textobj->NUM_OF_BLOCKS);
	new_text->NUM_OF_BLOCKS = textobj->NUM_OF_BLOCKS;
	if (textobj->NUM_OF_BLOCKS > 0)
	{
		new_text->block_array[0] = cipher(IV, keyobj);
		new_text->block_array[0] = XOR(new_text->block_array, textobj->block_array);
	}
	for (long i = 1; i < textobj->NUM_OF_BLOCKS; ++i)
	{
		new_text->block_array[i] = cipher(new_text->block_array + (i-1), keyobj);
		new_text->block_array[i] = XOR(new_text->block_array + i, textobj->block_array + i);
	}
	return new_text;
}
struct text* CFB_decrypt_MODE(struct text* textobj, struct block* IV, struct key* keyobj)
{

	struct text* new_text = malloc(sizeof(struct text));
	new_text->block_array = malloc(sizeof(struct block) * textobj->NUM_OF_BLOCKS);
	new_text->NUM_OF_BLOCKS = textobj->NUM_OF_BLOCKS;
	if (textobj->NUM_OF_BLOCKS > 0)
	{	
		new_text->block_array[0] = cipher(IV, keyobj);
		new_text->block_array[0] = XOR(new_text->block_array, textobj->block_array);
	}
	for (long i = 1; i < textobj->NUM_OF_BLOCKS; ++i)
	{
		new_text->block_array[i] = cipher(textobj->block_array + (i-1), keyobj);
		new_text->block_array[i] = XOR(new_text->block_array + i, textobj->block_array + i);
	}
	return new_text;
}
//Counter Mode
//The last 32 bits of IV is used for the counter
struct text* CTR_MODE(struct text* textobj, struct block* IV, struct key* keyobj)
{
	struct text* new_text = malloc(sizeof(struct text));
	new_text->block_array = malloc(sizeof(struct block) * textobj->NUM_OF_BLOCKS);
	new_text->NUM_OF_BLOCKS = textobj->NUM_OF_BLOCKS;
	for (long i = 0; i < new_text->NUM_OF_BLOCKS; ++i)
	{
		new_text->block_array[i] = cipher(IV, keyobj);
		new_text->block_array[i] = XOR(new_text->block_array + i, textobj->block_array + i);
		IV->R0 += 1;
		if (IV->R0 == 0)
			IV->R1 += 1;
	}	
	return new_text;	
}
void usage(char** argv)
{
	printf("usage: %s [-options] key_file text_file\n", argv[0]);
}
//The purpose of main is to parse command line options and arguments
int main(int argc, char** argv)
{
// command line options
	enum {ECB, CBC, OFB, CFB, CTR}operation; //mode of operation to run
	int option; //variable that holds command line options
	struct text* (*mode)(struct text*, struct block*, struct key*); //function pointer to function performing mode of operation
	void (*print)(struct text*, FILE*); //function pointer to function printing blocks of text (hex/ascii versions)
	struct text* (*read_in)(FILE* FP); //function pointer to function reading in text from file (hex/ascii versions)	
	KEY_SIZE = 80; //default parameter for number of bits in key
	KEY_BYTES = 10;
	FILE* output = stdout; //By default the output of the mode of operation goes to stdout
	print = print_hex; //Default mode is encryption, so prints ciphertext in hex
	read_in = read_in_characters; //Plaintext is assummed to be in ascii
	cipher = feistel_encrypt; //Default mode is encryption	
	char* file_arg = NULL; //Holds file to output to if user doesn't want to send to stdout
	operation = ECB; //Electronic Code Book is the default mode
	struct block* IV = NULL; //Initialization Vector
	FILE* FP = NULL;//File pointer for input files	
	while(((option = getopt(argc, argv, "b:m:srdef:i:")) != -1)) //Parse command line options
	{
		switch (option)
		{
			case 'b': //Key bits
				KEY_SIZE = atoi(optarg);
				KEY_BYTES = KEY_SIZE / 8;
				break;
			case 'm'://Mode of Operation
				if (!strcmp(optarg, "ECB"))
					operation = ECB;
				else if (!strcmp(optarg, "CBC"))
					operation = CBC;
				else if (!strcmp(optarg, "OFB"))
					operation = OFB;
				else if (!strcmp(optarg, "CFB"))
					operation = CFB;
				else if (!strcmp(optarg, "CTR"))
					operation = CTR;	
				else
				{
					printf("unknown mode\n");
					exit(EXIT_FAILURE);
				}
				break;
			case 's'://Print out subkeys  
				PRINT_SUBKEYS = true;
				break;
			case 'r'://Print out each round of feistel cipher
				PRINT_ROUNDS = true;
				break;
			case 'd'://Decrypt Mode
				read_in = read_in_hex;
				print = print_characters;
				break;
			case 'e'://Encrypt Mode
				cipher = feistel_encrypt;	
				read_in = read_in_characters;
				print = print_hex;
				break;
			case 'f'://Store result in File
				file_arg = malloc((strlen(optarg) + 1 ) * sizeof(char));
				strcpy(file_arg, optarg);
				break;
			case 'i'://Get initialization Vector from File
				{
					if (!(FP = fopen(optarg, "r")))
					{
						printf("unable to open initialization vector file\n");
						exit(EXIT_FAILURE);		
					}
				}
				break;
				
		}
	}
	if (print == print_hex) //Encrypt mode
	{
		switch(operation)
		{
			case ECB:
				mode = ECB_MODE;
				break;
			case CBC:
				mode = CBC_encrypt_MODE;
				break;
			case OFB:
				mode = OFB_MODE;
				break;
			case CFB:
				mode = CFB_encrypt_MODE;
				break;
			case CTR:
				mode = CTR_MODE;	
				break;	
		}		
	}
	else //Decrypt Mode
	{
		switch(operation)
		{
			case ECB:
				mode = ECB_MODE;
				cipher = feistel_decrypt;
				break;
			case CBC:
				mode = CBC_decrypt_MODE;
				cipher = feistel_decrypt;	
				break;	
			case OFB:
				mode = OFB_MODE;
				cipher = feistel_encrypt;
				break;
			case CFB:
				mode = CFB_decrypt_MODE;
				cipher = feistel_encrypt;
				break;
			case CTR:
				mode = CTR_MODE;
				cipher = feistel_encrypt;
				break;
		}
	}
	if (!FP) //default initialization vector
	{
		IV = malloc(sizeof(struct block));
		IV->R0 = 0x0123;
		IV->R1 = 0x4567;
		IV->R2 = 0x89AB;
		IV->R3 = 0xCDEF;
	}
	else if (!(IV = read_IV(FP)))

	{
		printf("initialization vector file needs to be 64 bits in hex format");
		exit(EXIT_FAILURE);
	}
	struct text* textobj = NULL;
	struct text* new_text = NULL;
	struct key keyobj;
	keyobj.key_byte = malloc(sizeof(unsigned char) * KEY_SIZE);
	keyobj.set_mode = set_mode;
	keyobj.set_mode(&keyobj, 'e');
	if (optind + 2 == argc)
	{
		if (!(FP = fopen(argv[optind], "r")))
		{
			printf("unable to open %s\n", argv[optind]);
			goto MEMORY;
		}
		if(keyobj.input_key(&keyobj, FP) < 0)
		{
			printf("%s does not contain an %d bit key\n", argv[optind], KEY_SIZE);
			goto MEMORY;
		}
		fclose(FP);
		FP = fopen(argv[optind + 1], "r");
		if (!(textobj =read_in(FP)))
		{
			printf("%s not found or has wrong format\n", argv[optind + 1]);
			goto MEMORY;	
		}
		
		if (file_arg)
			output = fopen(file_arg, "w");
		fclose(FP);
	}
	else //invalid number of arguments
	{
		usage(argv);
		goto MEMORY;
	}
	
	if (PRINT_SUBKEYS) //Prints subkeys if option is turned on
	{
		bool ROUND_PRINT = PRINT_ROUNDS;
		PRINT_ROUNDS = false;
		//text is not important
		struct block obj;
		obj.R0 = 0x7365;
		obj.R1 = 0x6375;
		obj.R2 = 0x7269;
		obj.R3 = 0x7479;
		feistel_encrypt(&obj, &keyobj);
		PRINT_ROUNDS = ROUND_PRINT;
		PRINT_SUBKEYS = false;
	}

	new_text = mode(textobj, IV, &keyobj); //Performs the mode of operation
	print(new_text, output); //Prints out result to output	
	//Deallocate memory
	MEMORY:
	if (textobj)
	{
		free(textobj->block_array);
		free(textobj);
	}
	if (new_text)
	{
		free(new_text->block_array);
		free(new_text);
	}
	if (keyobj.key_byte)
		free(keyobj.key_byte);
	if (IV)	
		free(IV);
	if (file_arg)
	{
		fclose(output);
		free(file_arg);
	}
}

