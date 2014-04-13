struct sockit_payload {
	unsigned char midstate[32];
	unsigned int junk[8];
	unsigned m7;
	unsigned ntime;
	unsigned nbits;
	unsigned nnonce;
};

struct sockit_device {
	uint32_t *regs;
	struct sockit_payload payload;
};
