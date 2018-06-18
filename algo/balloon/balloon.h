#include <stdbool.h>
#include <stdint.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <inttypes.h>

#define BITSTREAM_BUF_SIZE ((32) * (AES_BLOCK_SIZE))
#define N_NEIGHBORS (3)
#define SALT_LEN (32)
#define INLEN_MAX (1ull<<20)
#define TCOST_MIN 1ull
#define SCOST_MIN (1)
#define SCOST_MAX (UINT32_MAX)
#define BLOCKS_MIN (1ull)
#define THREADS_MAX 4096
#define BLOCK_SIZE (32)
#define UNUSED __attribute__ ((unused))
#define HEADER_SIZE (80)
#define S_COST (128)
#define T_COST (4)
#define N_BLOCKS ((S_COST * 1024) / BLOCK_SIZE)


struct hash_state
{
  int64_t counter;
  uint8_t* buffer;
  uint8_t* zeros;
  SHA256_CTX sha_ctx;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX *evp_ctx;
#else
  EVP_CIPHER_CTX evp_ctx;
#endif
  uint64_t _ALIGN(16) neighbor[49152];
};


void balloon_128 (unsigned char *input, unsigned char *output);
void balloon_hash (unsigned char *input, unsigned char *output, int64_t s_cost, int32_t t_cost);
void balloon (unsigned char *input, unsigned char *output, int32_t len, int64_t s_cost, int32_t t_cost);

//void bitstream_init (struct bitstream *b);
//void bitstream_free (struct bitstream *b);
// void bitstream_seed_add (struct bitstream *b, const void *seed, size_t seedlen);
//void bitstream_seed_finalize (struct hash_state *s);
//void bitstream_fill_buffer (struct bitstream *b, void *out, size_t outlen);
//void compress (uint64_t *counter, uint8_t *out, const uint8_t *blocks[], size_t blocks_to_comp);
//void expand (uint64_t *counter, uint8_t *buf, size_t blocks_in_buf);
//uint64_t bytes_to_littleend_uint64 (const uint8_t *bytes, size_t n_bytes);
//void hash_state_init (struct hash_state *s, const uint8_t salt[SALT_LEN]);
//void hash_state_free (struct hash_state *s);
//void hash_state_fill (struct hash_state *s, const uint8_t *in, size_t inlen);
//void hash_state_mix (struct hash_state *s);
//void hash_state_extract (const struct hash_state *s, uint8_t out[BLOCK_SIZE]);
//void * block_index (const struct hash_state *s, size_t i); 
//void * block_last (const struct hash_state *s);