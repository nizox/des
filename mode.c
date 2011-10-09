#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <err.h>

#include "des.h"

void des_mode_ebc(struct des *des, unsigned char *buf, long len)
{
	for (len -= 8; len >= 0; len -= 8)
		des_cipher_block(des, buf + len);
}
