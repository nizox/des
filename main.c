#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <err.h>

#include "des.h"

void usage(void);

/* default settings */
static struct des des = {
	.op =	ENCRYPT,
	.mode = EBC,
	.ifd =	-1,
	.ofd =	-1,
	.bufsize = 8192,
};

/* check validity of parameters (files, ...) exit on failure */
static void des_init(void)
{
	if (des.ipath == NULL || des.opath == NULL) {
		usage();
		/* NOTREACHED */
	}
	if ((des.ifd = open(des.ipath, O_RDONLY)) == -1)
		err(1, "can't open input file %s", des.ipath);
	if ((des.ofd = open(des.opath, O_WRONLY | O_TRUNC | O_CREAT, 0644)) == -1)
		err(1, "can't open output file %s", des.opath);

	switch (des.mode) {
	case EBC:
		des.encrypt = des_mode_ebc;
		break;
	default:
		fprintf(stderr, "des: unknown mode used\n");
		exit(1);
	}

	/* Keying option 2 K1 and K2 are independent and K3 = K1 */
	if (des.step == 2)
		memcpy(des.keys[des.step++], des.keys[0], 8);
	/* K1 and K3 must be swaped for decryption */
	if (des.op == DECRYPT && des.step == 3) {
		unsigned char tmp[8];

		memcpy(tmp, des.keys[2], 8);
		memcpy(des.keys[2], des.keys[0], 8);
		memcpy(des.keys[0], tmp, 8);
	}
}

static void des_encrypt(void)
{
	unsigned char *buf;
	int step;
	long buflen, bytes, pad;

	buf = malloc(des.bufsize);
	if (buf == NULL)
		err(1, "cannot allocation required buffer");

	do
	{
		buflen = 0;
		while (buflen != des.bufsize
		    && (bytes = read(des.ifd, buf + buflen, des.bufsize - buflen)))
		{
			if (bytes == -1 && errno == EINTR) continue;
			else if (bytes < 0) break;
			buflen += bytes;
		}
		for (pad = buflen % 8; pad && pad < 8; ++pad)
			buf[buflen++] = 0;
		step = des.step;
		for (des.step = 0; des.step < step; ++des.step) {
			des.encrypt(&des, buf, buflen);
			des.op = (des.op == ENCRYPT) ? DECRYPT : ENCRYPT;
		}
		des.step = step;
		des.op = (des.op == ENCRYPT) ? DECRYPT : ENCRYPT;
		write(des.ofd, buf, buflen);
	}
	while (buflen == des.bufsize);
	free(buf);
}

int main(int argc, char *argv[])
{
	int ch;
	int i, len;

	while ((ch = getopt(argc, argv, "dei:o:k:")) != -1)
		switch (ch) {
		case 'd':
			des.op = DECRYPT;
			break;
		case 'e':
			des.op = ENCRYPT;
			break;
		case 'i':
			des.ipath = optarg;
			break;
		case 'o':
			des.opath = optarg;
			break;
		case 'k':
			if (des.step < 3) {
				for (i = 0, len = MIN(strlen(optarg), 24); i < len; ++i) {
					if (i && i % 8 == 0) ++des.step;
					des.keys[des.step][i % 8] = optarg[i];
				}
				++des.step;
				break;
			}
		default:
			usage();
			/* NOTREACHED */
		}

	des_init();
	for (i = 0; i < des.step; ++i) {
		des_key_permute(des.keys[i]);
		des_generate_subkeys(des.keys[i], des.subkeys[i]);
	}
	des_encrypt();

	return 0;
}

void usage(void)
{
	fprintf(stderr, "usage: des [-de] [-i infile] [-o outfile] [-k=key]\n"
	    "-e\t encrypt infile to outfile using key\n"
	    "-d\t decrypt infile to outfile using key\n");
	exit(1);
}
