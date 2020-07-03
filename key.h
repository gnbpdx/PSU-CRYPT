#include <stdint.h>
#include <stdio.h>
struct key
{
	unsigned char* key_byte;
	void (*rotate)(struct key*);
	unsigned char (*K)(struct key*, unsigned int);
	int (*input_key)(struct key*, FILE*);
	int (*set_mode)(struct key*, char);

};
