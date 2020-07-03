struct block
{
	unsigned int R0: 16;
	unsigned int R1: 16;
	unsigned int R2: 16;
	unsigned int R3: 16;
};
struct subblock
{
	unsigned int R0: 16;
	unsigned int R1: 16;
};
struct G_block
{
	unsigned int g1: 8;
	unsigned int g2: 8;
};
struct text
{
	struct block* block_array;
	long NUM_OF_BLOCKS;
};
