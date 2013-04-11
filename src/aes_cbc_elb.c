/* vim: set expandtab cindent fdm=marker ts=2 sw=2: */

/* {{{ Copyright notice

Copyright (C) 2013 Jirka Hladky <hladky DOT jiri AT gmail DOT com>

This file is part of IAESNI project http://code.google.com/p/csrng/

CSRNG is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

CSRNG is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with CSRNG.  If not, see <http://www.gnu.org/licenses/>.
}}} */

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "iaesni.h"

#define BLOCK_SIZE (16) //in bytes


void *util_Malloc (size_t size)
{
   void *p;
   errno = 0;
   p = malloc (size);
   if (p == NULL) {
      fprintf (stderr, "\nmalloc failed: %s\n\n", strerror (errno));
      exit (EXIT_FAILURE);
      return NULL;     /* to eliminate a warning from the compiler */
   } else
      return p;
}

void *util_Calloc (size_t count, size_t esize)
{
   void *p;
   errno = 0;
   p = calloc (count, esize);
   if (p == NULL) {
      fprintf (stderr, "\ncalloc failed: %s\n\n", strerror (errno));
      exit (EXIT_FAILURE);
      return NULL;     /* to eliminate a warning from the compiler */
   } else
      return p;
}

void *util_Realloc (void *ptr, size_t size)
{
   void *p;
   errno = 0;
   p = realloc (ptr, size);
   if ((p == NULL) && (size != 0)) {
      fprintf (stderr, "\nrealloc failed: %s\n\n", strerror (errno));
      exit (EXIT_FAILURE);
      return ptr;      /* to eliminate a warning from the compiler */
   } else
      return p;

}

void util_Free (void *p)
{
   if (p == NULL)
      return;
   free (p);
   return;
}

void usage (void) {
  fprintf(stderr, "aes_cbc_elb: tool to compute CBC-MAC-ELB (Encrypt-last-block) using AES]\n");
  fprintf(stderr, "See http://en.wikipedia.org/wiki/CBC-MAC\n");
  fprintf(stderr, "Usage: aes_cbc_elb -m <128 | 192 | 256> -k <key in hex format, length is 16, 24 or 32 bytes> -e <key in hex fomat> [FILE]\n"
      "-m Mode for the AES encryption\n"
      "-k Key for the AES encryption of length 16, 24 or 32 bytes\n"
      "-e Key for the final encryption (Encrypt-last-block)\n"
      "FILE File for which CBC_EMAC will be computed - if not specified, STDIN will be used\n");
}

int  main(int argc, char **argv) {

	// verify that AESNI support exists on the platform
	if (check_for_aes_instructions() == 0) {
		fprintf(stderr, "Intel AES New Instructions NOT detected on this platform - validation app will now terminate.\n");
		return 1;
	}
  char *key[2] = { NULL, NULL};  //main key and end_key 
  char *mode = NULL;
  char *endptr;
  long int mode_val;
  int c;
  unsigned int i,j;
  FILE* fd;
  const unsigned int aes_block_size = 16;                    //Size of the data blocks - 16 Bytes
  const unsigned int step_size = 1024;                       //How much aes_blocks do we process at once


  opterr = 0;

  while ((c = getopt (argc, argv, "m:k:e:")) != -1)
    switch (c) {
      case 'k':
        key[0] = optarg;
        break;
      case 'e':
        key[1] = optarg;
        break;
      case 'm':
        mode = optarg;
        break;
      case '?':
        if (optopt == 'k')
          fprintf (stderr, "Option -%c requires an argument.\n", optopt);
        else if (optopt == 'e')
          fprintf (stderr, "Option -%c requires an argument.\n", optopt);
        else if (optopt == 'm')
          fprintf (stderr, "Option -%c requires an argument.\n", optopt);
        else if (isprint (optopt))
          fprintf (stderr, "Unknown option `-%c'.\n", optopt);
        else
          fprintf (stderr,
              "Unknown option character `\\x%x'.\n",
              optopt);
        usage();
        return 1;
      default:
        return 1;
    }

  if ( mode == NULL ) {
    fprintf(stderr, "-m  is required!\n");
    return 1;
  }


  for (i=0; i<2; ++i) {
    if ( key[i] == NULL ) {
      fprintf(stderr, "Both -k and -e are required!\n");
      return 1;
    }
  }

  if ( argc == optind ) {
    fd = stdin;
  } else if ( argc == optind + 1 ) {
    fd = fopen ( argv[optind], "r" );
    if ( fd == NULL ) fprintf(stderr, "ERROR: Cannot open file '%s' for reading. Reported error: %s\n", argv[optind], strerror(errno));
  } else {
      fprintf(stderr, "Unexpected arguments\n");
      optind++;
      while (optind < argc) printf("'%s'\n", argv[optind++]);
      return 1;
  }
    
  errno = 0;
  mode_val = strtol(mode, &endptr, 10);
  if ((errno == ERANGE && (mode_val == LONG_MAX || mode_val == LONG_MIN))
      || (errno != 0 && mode_val == 0)
      || (endptr == mode)
      || (*endptr !=0) ) {
    fprintf(stderr, "Error when parsing -m value \'%s\'\n", mode);
    return 1;
  }

  if ( mode_val != 128 && mode_val != 192 && mode_val != 256 ) {
    fprintf (stderr, "Mode has to be one of 128, 192, 256. Got %ld.\n", mode_val);
    return 1;
  }

  for (i=0; i<2; ++i) {
    if ( strlen(key[i]) != (unsigned long) mode_val/4 ) {
      fprintf (stderr, "Key '%s': length has to be %ld Bytes but is %zu\n", key[i], mode_val/4, strlen(key[i]) );
      return 1;
    }
  }

  UCHAR* aes_key[2];
  char parse_byte[3];
  parse_byte[2] = '\0';

  for (i=0; i<2; ++i) {
    aes_key[i] = util_Calloc(mode_val/8, 1);

    for (j=0; j<mode_val/4; ++j) {
      if ( isxdigit ( key[i][j] ) ) {
        parse_byte[j%2] = key[i][j];
      } else {
        fprintf (stderr, "Invalid char in key %s.\nExpecting 16-bit number, got `%c`\n", key[i], key[i][j] );
        return 1;
      }
      if ( j%2 == 1 ) {
        aes_key[i][j/2] = strtol(parse_byte, NULL, 16);
        //fprintf(stderr, "%s -> %d\n", parse_byte, aes_key[i][j/2]);
      }
    }

    fprintf(stdout, "Parsed key:\t");
    for (j=0; j<mode_val/8; ++j) {
      fprintf(stdout, "%02x", aes_key[i][j]);
    }
    fprintf(stdout, "\n");
  }

  for (i=0; i<2; ++i) {
    util_Free(aes_key[i]);
  }

  UCHAR* input_data;
  UCHAR* output_data;
  UCHAR* iv;
  size_t bytes_read, blocks;

  input_data = util_Calloc(step_size * aes_block_size, 1);
  output_data = util_Calloc(step_size * aes_block_size, 1);
  iv = util_Calloc(aes_block_size, 1);


  void (*intel_AES_enc)(UCHAR*, UCHAR*, UCHAR* key, size_t);
  void (*intel_AES_enc_CBC)(UCHAR*, UCHAR*, UCHAR* key, size_t, UCHAR* iv);
  switch (mode_val) {
    case 128:
      intel_AES_enc = &intel_AES_enc128;
      intel_AES_enc_CBC = &intel_AES_enc128_CBC;
      break;
    case 192:
      intel_AES_enc = &intel_AES_enc192;
      intel_AES_enc_CBC = &intel_AES_enc192_CBC;
      break;
    case 256:
      intel_AES_enc = &intel_AES_enc256;
      intel_AES_enc_CBC = &intel_AES_enc256_CBC;
      break;
  }
    
  while ( (bytes_read = fread (input_data, 1, aes_block_size * step_size, fd)) == aes_block_size * step_size ) {
    intel_AES_enc_CBC(input_data, output_data, aes_key[0], step_size, iv);
    memcpy(iv, output_data + (step_size - 1) * aes_block_size, aes_block_size);
  }

  if (feof(fd)) {
    //EOF handling
    blocks = bytes_read / aes_block_size;
    if ( bytes_read % aes_block_size > 0 ) {
      input_data[blocks] = 128;
      if ( bytes_read % aes_block_size > 1 ) {
        memset(input_data + blocks + 1, 0, bytes_read % aes_block_size - 1);
      } 
      ++blocks;
    }
    if ( blocks > 0 ) {
      intel_AES_enc_CBC(input_data, output_data, aes_key[0], blocks, iv);
    }

    //Final Encryption
    memcpy(input_data, output_data + (blocks - 1) * aes_block_size, aes_block_size);
    intel_AES_enc (input_data, output_data, aes_key[1], 1);
    
  } else {
    fprintf(stderr,"fread: ERROR: %s\n", strerror(errno));
    return 1;
  }

    fprintf(stderr, "CBC_EMAC:\t");
    for (j=0; j < aes_block_size; ++j) {
      fprintf(stdout, "%02x", output_data[j]);
    }
    fprintf(stdout, "\n");


	return 0;
}
