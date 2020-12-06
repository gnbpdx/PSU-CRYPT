#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#define BYTE 8
enum integer {PRIME, COMPOSITE};
struct text
{
	uint32_t* text1;
	uint32_t* text2;
	uint64_t blocks;
};
uint64_t random_generator(uint64_t min, uint64_t max)
{
	uint64_t random = rand();
	random %= (max - min + 1);
	random +=min;
	return random;
}
uint64_t square_and_multiply(uint32_t base, uint32_t exponent, uint32_t modulus)
{
	uint64_t result = base;
	int bits = 0;
	for (int i = 31; i >= 0; i--)
	{
		if ((exponent >> i) & 1)
		{
			bits = i;
			break;
		}
	}
	if (bits == 0)
		return (exponent) ? base : 1;
	for (int i = bits - 1; i >= 0; --i)
	{
		result *= result;
		result %= modulus;
		if (exponent & (1 << (uint64_t)i))
		{
			result *= base;
			result %= modulus; 
		}
	}
	return result;
}
enum integer miller_rabin(int32_t prime, uint32_t s)
{
	for (uint32_t i = 0; i < s; ++i)
	{
		uint32_t a = random_generator(2, prime-2);
		uint32_t u = 0;
		uint32_t r = prime - 1;
		while(r % 2 == 0)
		{
			++u;
			r /= 2;
		}
		uint64_t z = square_and_multiply(a, r, prime);
		if (z == 1 || z == prime - 1)
			continue;
		for (uint32_t j = 1; j < u; ++j)
		{
			z *= z;
			z %= prime;
			if (z == 1)
				return COMPOSITE;
			if (z == prime - 1)
				break;
		}
		if (z != prime - 1)
			return COMPOSITE;


	}
	return PRIME;
}
uint64_t safe_prime(uint32_t s)
{
	bool is_prime = false;
	uint64_t q = 0;
	uint64_t p = 0;
	do
	{
		q = random_generator(0x40000000, 0x7FFFFFFF);
		if (q % 2 == 0)
			continue;
		if (miller_rabin(q, s) == PRIME)
		{
			if ((q % 12) != 5)
				continue;
			p = q * 2 + 1;
			if(miller_rabin(p, s) == PRIME)
				is_prime = true;
		}
	} while (is_prime == false);
	return p;
}
int key_generation(FILE* private_key, FILE* public_key, uint32_t s)
{
	uint32_t p = safe_prime(s);
	uint32_t g = 2;
	uint32_t d = random_generator(1, p - 1);
	uint32_t e2 = square_and_multiply(g, d, p);
	if (!private_key || !public_key)
		return -1;
	fprintf(private_key, "%" PRIu32 " %" PRIu32  " %" PRIu32 "\n", p,g,d);
	fprintf(public_key, "%" PRIu32  " %"PRIu32  " %" PRIu32 "\n", p,g,e2);
	return 0;
}
struct text* read_in(FILE* input)
{
	if (!input)
		return NULL;
	char buffer[5];
	struct text* new_text = malloc(sizeof(struct text));
	new_text->blocks = 0;
	new_text->text1 = NULL;
	new_text->text2 = NULL;
	while (fgets(buffer, 5, input) > 0)
	{
		if (strlen(buffer) < 4)
		{
			while(fgets(buffer + strlen(buffer), 5 - strlen(buffer), input) > 0 && strlen(buffer) < 4)
			{}
		}
		++new_text->blocks;
		new_text->text1 = realloc(new_text->text1, new_text->blocks*sizeof(uint32_t));
		new_text->text1[new_text->blocks - 1] = 0;
		for (int i = 0; i < 4; ++i)
		{
			new_text->text1[new_text->blocks -1] += buffer[i] << BYTE * i;
			buffer[i] = '\0';
		}
	}
	return new_text;
}
struct text* read_in_ciphertext(FILE* input)
{
	if (!input)
		return NULL;
	char buffer[5];
	struct text* new_text = malloc(sizeof(struct text));
	new_text->blocks = 0;
	new_text->text1 = NULL;
	new_text->text2 = NULL;
	uint32_t temp1;
	uint32_t temp2;
	while(fscanf(input, "%" PRIu32 " %" PRIu32, &temp1, &temp2) > 0)
	{
		++new_text->blocks;
		new_text->text1 = realloc(new_text->text1, new_text->blocks*sizeof(uint32_t));
		new_text->text2 = realloc(new_text->text2, new_text->blocks*sizeof(uint32_t));
		new_text->text1[new_text->blocks - 1] = temp1;
		new_text->text2[new_text->blocks - 1] = temp2;
	}
	return new_text;
}
void write_out(struct text* data, FILE* output)
{
	if (!output)
		return;
	for (uint64_t i = 0; i < data->blocks; ++i)
	{
		fprintf(output, "%" PRIu32 " %" PRIu32 " ", data->text1[i], data->text2[i]);
	}
}
void write_out_plain(struct text* data, FILE* output)
{
	if (!output)
		return;
	for (uint64_t i = 0; i < data->blocks; ++i)
	{
		char temp1 = 0xFF & data->text1[i];
		char temp2 = 0xFF & (data->text1[i] >> BYTE);
		char temp3 = 0xFF & (data->text1[i] >> 2*BYTE);
		char temp4 = 0xFF & (data->text1[i] >> 3*BYTE);
		fprintf(output, "%c%c%c%c", temp1, temp2, temp3, temp4);
	}
	
}
struct text* encryption(struct text* input, FILE* public_key)
{
	if (!public_key)
		return NULL;
	uint32_t p,g,e2;
	fscanf(public_key, "%" PRIu32 " %" PRIu32 " %" PRIu32, &p, &g, &e2);
	struct text* new_text = malloc(sizeof(struct text));
	new_text->blocks = input->blocks;
	new_text->text1 = malloc(new_text->blocks*sizeof(uint32_t));
	new_text->text2 = malloc(new_text->blocks*sizeof(uint32_t));
	for (uint64_t i = 0; i < input->blocks; ++i)
	{
		uint32_t k = random_generator(0, p-1);
		uint32_t c1 = square_and_multiply(g, k, p);
		uint64_t c2 = square_and_multiply(e2, k, p);
		c2 *= input->text1[i];
		c2 %= p;
		new_text->text1[i] = c1;
		new_text->text2[i] = c2;
	}
	return new_text;
}
struct text* decryption(struct text* input, FILE* private_key)
{
	if (!private_key)
		return NULL;
	uint32_t p,g,d;
	fscanf(private_key, "%" PRIu32 " %" PRIu32 " %" PRIu32, &p, &g, &d);
	struct text* new_text = malloc(sizeof(struct text));
	new_text->blocks = input->blocks;
	new_text->text1 = malloc(input->blocks*sizeof(uint32_t));
	for (uint64_t i = 0; i < input->blocks; ++i)
	{
		uint64_t m = square_and_multiply(input->text1[i], p - 1 - d, p);
		uint64_t c2 = input->text2[i] % p;
		m *= c2;
		m %= p;
		new_text->text1[i] = m;

	}
	return new_text;
	

}
int main(int argc, char** argv)
{
	srand(time(NULL));
	
	if ((argc > 3) || (argc < 2))
	{
		printf("%s has an incorrect number of arguments\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	if (!strcmp(argv[1], "encrypt"))
	{
		if (argc != 2)
		{
			printf("Incorrect number of arguments\n");
			exit(EXIT_FAILURE);
		}
		FILE* PUBLIC = fopen("pubkey.txt", "r");
		FILE* PLAINTEXT = fopen("ptext.txt", "r");
		FILE* CIPHERTEXT = fopen("ctext.txt", "w");
		struct text* plain = read_in(PLAINTEXT);
		struct text* cipher = encryption(plain, PUBLIC);
		write_out(cipher, CIPHERTEXT);
		free(plain->text1);
		free(plain);
		free(cipher->text1);
		free(cipher->text2);
		free(cipher);
		fclose(PUBLIC);
		fclose(PLAINTEXT);
		fclose(CIPHERTEXT);

	}
	else if (!strcmp(argv[1], "decrypt"))
	{
		if (argc != 2)
		{
			printf("Incorrect number of arguments\n");
			exit(EXIT_FAILURE);
		}
		FILE* PRIVATE = fopen("prikey.txt", "r");
		FILE* CIPHERTEXT = fopen("ctext.txt", "r");
		FILE* PLAINTEXT = fopen("dtext.txt", "w");
		struct text* cipher = read_in_ciphertext(CIPHERTEXT);
		struct text* plain = decryption(cipher, PRIVATE);
		write_out_plain(plain, PLAINTEXT);
		free(cipher->text1);
		free(cipher->text2);
		free(cipher);
		free(plain->text1);
		free(plain);
		fclose(PRIVATE);
		fclose(CIPHERTEXT);
		fclose(PLAINTEXT);
	}
	else if (!strcmp(argv[1], "keygeneration"))
	{
		if (argc != 2)
		{
			printf("Key generation has too many arguments\n");
			exit(EXIT_FAILURE);
		}
		//unsigned int seed = atoi(argv[2]);
		//srand(seed);
		FILE* PRIVATE = fopen("prikey.txt", "w");
		FILE* PUBLIC = fopen("pubkey.txt", "w");
		int val = key_generation(PRIVATE, PUBLIC, 10);
		fclose(PRIVATE);
		fclose(PUBLIC);
	}
	else
	{
		printf("Incorrect argument entered.\n");
		exit(EXIT_FAILURE);
		
	}
	return 0;
}

