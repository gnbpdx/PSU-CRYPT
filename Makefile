psu-crypt: key.c block.c feistel.c modes.c
	gcc -std=c11 -o psu-crypt key.c block.c feistel.c modes.c
