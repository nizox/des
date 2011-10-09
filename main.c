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
	.bufsize = 4096,
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
}

static void des_encrypt(void)
{
	unsigned char *buf;
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
		des.encrypt(&des, buf, buflen);
		write(des.ofd, buf, buflen);
	}
	while (buflen == des.bufsize);
	free(buf);
}

int main(int argc, char *argv[])
{
	int ch;

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
			memcpy(des.key, optarg, MIN(strlen(optarg), 8));
			break;
		default:
			usage();
			/* NOTREACHED */
		}

	des_init();
	des_key_permute(des.key);
	des_generate_subkeys(des.key, des.subkeys);
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
