#ifndef GLOBALS_H
#define GLOBALS_H
#include <stdbool.h>
extern bool PRINT_SUBKEYS;
extern bool PRINT_ROUNDS;
extern int KEY_SIZE;
extern int KEY_BYTES;
extern int set_mode(struct key*, char);
extern struct block whiten(struct block*, struct key*);
extern struct text* read_in_characters(FILE*);
extern struct text* read_in_hex(FILE*);
extern struct block* read_IV(FILE*);
extern struct block* read_IV_CTR(FILE*);
extern struct block feistel_encrypt(struct block*, struct key*);
extern struct block feistel_decrypt(struct block*, struct key*);
extern struct block XOR(struct block*, struct block*);
extern void print_characters(struct text*, FILE*);
extern void print_hex(struct text*, FILE*);
extern struct subblock F(struct subblock*, unsigned int round, struct key*);
extern void encryption_rotate(struct key*);
#endif
