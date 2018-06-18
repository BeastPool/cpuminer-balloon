#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "algo-gate-api.h"
#include "compat.h"
#include "balloon.h"
// #include <emmintrin.h>
// #include <immintrin.h>

#if __STDC_VERSION__ >= 199901L
/* have restrict */
#elif defined(__GNUC__)
#define restrict __restrict
#else
#define restrict
#endif

static inline void balloon_init(struct hash_state *restrict s)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  s->evp_ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(s->evp_ctx);
#else
  EVP_CIPHER_CTX_init(&s->evp_ctx);
#endif
  s->zeros = malloc(BITSTREAM_BUF_SIZE);
  s->buffer = malloc(N_BLOCKS * BLOCK_SIZE);
  memset(s->zeros, 0, BITSTREAM_BUF_SIZE);
}

static inline void balloon_free(struct hash_state *restrict s)
{
  free(s->buffer);
  free(s->zeros);
}

static inline void evp_free(struct hash_state *restrict s)
{
  uint8_t out[AES_BLOCK_SIZE];
  int outl;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_EncryptFinal(s->evp_ctx, out, &outl);
  EVP_CIPHER_CTX_cleanup(s->evp_ctx);
  EVP_CIPHER_CTX_free(s->evp_ctx);
#else
  EVP_EncryptFinal(&s->evp_ctx, out, &outl);
  EVP_CIPHER_CTX_cleanup(&s->evp_ctx);
#endif
}

static inline void bitstream_fill_buffer(struct hash_state *restrict s, uint8_t *out, int32_t outlen)
{
  int encl;
  for (int i = 0; i < 393216; i += 512)
  {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    EVP_EncryptUpdate(s->evp_ctx, out + i, &encl, s->zeros, 512);
#else
    EVP_EncryptUpdate(&s->evp_ctx, out + i, &encl, s->zeros, 512);
#endif
  }
}

static inline void expand(struct hash_state *s, int32_t blocks_in_buf)
{
  uint8_t _ALIGN(16) data[40];
  uint8_t *cur = s->buffer + BLOCK_SIZE;
  const uint8_t *blocks = s->buffer;
  for (int i = 1; i < 4096; i++)
  {
    memcpy(&data[0], &s->counter, 8);
    memcpy(&data[8], blocks, 32);
    SHA256_Init(&s->sha_ctx);
    SHA256_Update(&s->sha_ctx, data, sizeof(data));
    SHA256_Final(cur, &s->sha_ctx);
    blocks += BLOCK_SIZE;
    cur += BLOCK_SIZE;
    s->counter++;
    // hate this function
  }
}

static inline void evp_init(struct hash_state *restrict s, const uint8_t salt[SALT_LEN])
{
  const int64_t s_cost = S_COST;
  const int32_t t_cost = T_COST;
  uint8_t key_bytes[SHA256_DIGEST_LENGTH];
  SHA256_Init(&s->sha_ctx);
  SHA256_Update(&s->sha_ctx, salt, SALT_LEN);
  SHA256_Update(&s->sha_ctx, &s_cost, 8);
  SHA256_Update(&s->sha_ctx, &t_cost, 4);
  SHA256_Final(key_bytes, &s->sha_ctx);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX_set_padding(s->evp_ctx, 1);
  EVP_EncryptInit(s->evp_ctx, EVP_aes_128_ctr(), key_bytes, NULL);
#else
  EVP_CIPHER_CTX_set_padding(&s->evp_ctx, 1);
  EVP_EncryptInit(&s->evp_ctx, EVP_aes_128_ctr(), key_bytes, NULL);
#endif
}

static inline void hash_state_fill(struct hash_state *restrict s, const uint8_t *in)
{
  const int64_t s_cost = S_COST;
  const int32_t t_cost = T_COST;
  uint8_t _ALIGN(16) data[132];

  s->counter = 0;

  memcpy(&data[0], &s->counter, 8);
  memcpy(&data[8], in, SALT_LEN);
  memcpy(&data[40], in, HEADER_SIZE);
  memcpy(&data[120], &s_cost, 8);
  memcpy(&data[128], &t_cost, 4);

  SHA256_Init(&s->sha_ctx);
  SHA256_Update(&s->sha_ctx, data, sizeof(data));
  SHA256_Final(s->buffer, &s->sha_ctx);

  s->counter++;

  expand(s, N_BLOCKS);
}

static inline void hash_state_pre_fill(struct hash_state *restrict s)
{
  uint8_t _ALIGN(16) buf[393216];
  bitstream_fill_buffer(s, buf, 393216);
  for (int i = 0; i < 49152; i++)
  {
    s->neighbor[i] = (((uint64_t *)buf)[i]) % 4096; // haha :P
  }
}

static void hash_state_mix(struct hash_state *s)
{
  uint8_t _ALIGN(16) data[168];
  const int32_t t_cost = T_COST;
  const int32_t n_blocks = N_BLOCKS;
  const int32_t block_size = BLOCK_SIZE;
  const uint8_t *blocks[5];
  uint8_t *s_buffer = s->buffer;
  uint8_t *last_block = s_buffer + 131040;
  uint64_t *s_neighbor = s->neighbor;
  for (int32_t rounds = 0; rounds < t_cost; rounds++)
  {
    for (int32_t i = 0; i < n_blocks; i++)
    {
      uint8_t *cur_block = (s_buffer + (block_size * i));
      *(blocks + 0) = (i ? cur_block - block_size : last_block);
      *(blocks + 1) = cur_block;
      *(blocks + 2) = (s_buffer + (block_size * (*(s_neighbor++))));
      *(blocks + 3) = (s_buffer + (block_size * (*(s_neighbor++))));
      *(blocks + 4) = (s_buffer + (block_size * (*(s_neighbor++))));

      memcpy(&data[0], &s->counter, 8);
      memcpy(&data[8], *(blocks + 0), 32);
      memcpy(&data[40], *(blocks + 1), 32);
      memcpy(&data[72], *(blocks + 2), 32);
      memcpy(&data[104], *(blocks + 3), 32);
      memcpy(&data[136], *(blocks + 4), 32);

      SHA256_Init(&s->sha_ctx);
      SHA256_Update(&s->sha_ctx, data, sizeof(data));
      SHA256_Final(cur_block, &s->sha_ctx);
      s->counter++;
    }
  }
}

static inline void hash_state_extract(const struct hash_state *restrict s, uint32_t *out)
{
  memcpy(out, s->buffer + 131040, BLOCK_SIZE);
}

void balloon_128(unsigned char *input, unsigned char *output)
{
  balloon(input, output, 80, 128, 4);
}

void balloon_hash(unsigned char *input, unsigned char *output, int64_t s_cost, int32_t t_cost)
{
  balloon(input, output, 80, s_cost, t_cost);
}

void balloon(unsigned char *input, unsigned char *output, int32_t len, int64_t s_cost, int32_t t_cost)
{
  struct hash_state s;
  balloon_init(&s);
  evp_init(&s, (const uint8_t *)input);
  hash_state_pre_fill(&s);
  evp_free(&s);
  hash_state_fill(&s, input);
  hash_state_mix(&s);
  hash_state_extract(&s, (uint32_t *)output);
  balloon_free(&s);
}

int scanhash_balloon(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
  uint32_t _ALIGN(64) hash32[8];
  uint32_t _ALIGN(64) endiandata[20];
  uint32_t *pdata = work->data;
  uint32_t *ptarget = work->target;

  const uint32_t Htarg = ptarget[7];
  const uint32_t first_nonce = pdata[19];

  uint32_t n = first_nonce;

  for (int i = 0; i < 19; i++)
  {
    be32enc(&endiandata[i], pdata[i]);
  }

  struct hash_state s;
  balloon_init(&s);
  bool init = false;

  do
  {
    be32enc(&endiandata[19], n);

    if (!init)
    {
      evp_init(&s, (const uint8_t *)endiandata);
      hash_state_pre_fill(&s);
      evp_free(&s);
      init = true;
    }

    hash_state_fill(&s, (const uint8_t *)endiandata);
    hash_state_mix(&s);
    hash_state_extract(&s, hash32);

    if (hash32[7] < Htarg && fulltest(hash32, ptarget))
    {
      work_set_target_ratio(work, hash32);
      *hashes_done = n - first_nonce + 1;
      pdata[19] = n;
      return true;
    }
    n++;

  } while (n < max_nonce && !work_restart[thr_id].restart);

  *hashes_done = n - first_nonce + 1;
  pdata[19] = n;

  balloon_free(&s);

  return 0;
}

bool register_balloon_algo(algo_gate_t *gate)
{
  gate->scanhash = (void *)&scanhash_balloon;
  gate->hash = (void *)&balloon_128;
  gate->set_target = (void *)&scrypt_set_target;
  gate->optimizations = SSE2_OPT | AVX2_OPT | AVX512_OPT;
  return true;
}