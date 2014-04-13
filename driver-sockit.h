struct sockit_device {
	uint32_t *regs;
	uint32_t midstate[8];
	uint32_t block1[3];
	uint32_t target[8];
	uint32_t start_nonce;
};
