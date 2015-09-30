#include <openssl/rsa.h>

#include <string.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include "openssl/mem.h"
#include <openssl/thread.h>

#include "crypto/rsa/internal.h"
#include "crypto/internal.h"
#include "my_engine.h"

#define OPENSSL_RSA_MAX_MODULUS_BITS 16384
#define OPENSSL_RSA_SMALL_MODULUS_BITS 3072
#define OPENSSL_RSA_MAX_PUBEXP_BITS \
  64 /* exponent limit enforced for "large" modulus only */


static int finish(RSA *rsa) {
  BN_MONT_CTX_free(rsa->_method_mod_n);
  BN_MONT_CTX_free(rsa->_method_mod_p);
  BN_MONT_CTX_free(rsa->_method_mod_q);

  if (rsa->additional_primes != NULL) {
    size_t i;
    for (i = 0; i < sk_RSA_additional_prime_num(rsa->additional_primes); i++) {
      RSA_additional_prime *ap =
          sk_RSA_additional_prime_value(rsa->additional_primes, i);
      BN_MONT_CTX_free(ap->method_mod);
    }
  }

  return 1;
}

static size_t size(const RSA *rsa) {
  return BN_num_bytes(rsa->n);
}

static int encrypt(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                   const uint8_t *in, size_t in_len, int padding) {
  const unsigned rsa_size = RSA_size(rsa);
  BIGNUM *f, *result;
  uint8_t *buf = NULL;
  BN_CTX *ctx = NULL;
  int i, ret = 0;
  printf("my encrypt\n");
  if (rsa_size > OPENSSL_RSA_MAX_MODULUS_BITS) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_MODULUS_TOO_LARGE);
    return 0;
  }

  if (max_out < rsa_size) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_OUTPUT_BUFFER_TOO_SMALL);
    return 0;
  }

  if (BN_ucmp(rsa->n, rsa->e) <= 0) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_BAD_E_VALUE);
    return 0;
  }

  /* for large moduli, enforce exponent limit */
  if (BN_num_bits(rsa->n) > OPENSSL_RSA_SMALL_MODULUS_BITS &&
      BN_num_bits(rsa->e) > OPENSSL_RSA_MAX_PUBEXP_BITS) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_BAD_E_VALUE);
    return 0;
  }

  ctx = BN_CTX_new();
  if (ctx == NULL) {
    goto err;
  }

  BN_CTX_start(ctx);
  f = BN_CTX_get(ctx);
  result = BN_CTX_get(ctx);
  buf = OPENSSL_malloc(rsa_size);
  if (!f || !result || !buf) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  switch (padding) {
    case RSA_PKCS1_PADDING:
      i = RSA_padding_add_PKCS1_type_2(buf, rsa_size, in, in_len);
      break;
    case RSA_PKCS1_OAEP_PADDING:
      /* Use the default parameters: SHA-1 for both hashes and no label. */
      i = RSA_padding_add_PKCS1_OAEP_mgf1(buf, rsa_size, in, in_len,
                                          NULL, 0, NULL, NULL);
      break;
    case RSA_NO_PADDING:
      i = RSA_padding_add_none(buf, rsa_size, in, in_len);
      break;
    default:
      OPENSSL_PUT_ERROR(RSA, RSA_R_UNKNOWN_PADDING_TYPE);
      goto err;
  }

  if (i <= 0) {
    goto err;
  }

  if (BN_bin2bn(buf, rsa_size, f) == NULL) {
    goto err;
  }

  if (BN_ucmp(f, rsa->n) >= 0) {
    /* usually the padding functions would catch this */
    OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
    goto err;
  }

  if (rsa->flags & RSA_FLAG_CACHE_PUBLIC) {
    if (BN_MONT_CTX_set_locked(&rsa->_method_mod_n, &rsa->lock, rsa->n, ctx) ==
        NULL) {
      goto err;
    }
  }

  printf("before my bn_mod_exp\n");

  if (!rsa->meth->bn_mod_exp(result, f, rsa->e, rsa->n, ctx,
                             rsa->_method_mod_n)) {
    goto err;
  }

  /* put in leading 0 bytes if the number is less than the length of the
   * modulus */
  if (!BN_bn2bin_padded(out, rsa_size, result)) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  *out_len = rsa_size;
  ret = 1;

err:
  if (ctx != NULL) {
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
  }
  if (buf != NULL) {
    OPENSSL_cleanse(buf, rsa_size);
    OPENSSL_free(buf);
  }

  return ret;
}

static int my_decrypt(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                   const uint8_t *in, size_t in_len, int padding) {
  const unsigned rsa_size = RSA_size(rsa);
  int r = -1;
  uint8_t *buf = NULL;
  int ret = 0;

  printf("my decrypt\n");

  if (max_out < rsa_size) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_OUTPUT_BUFFER_TOO_SMALL);
    return 0;
  }

  if (padding == RSA_NO_PADDING) {
    buf = out;
  } else {
    /* Allocate a temporary buffer to hold the padded plaintext. */
    buf = OPENSSL_malloc(rsa_size);
    if (buf == NULL) {
      OPENSSL_PUT_ERROR(RSA, ERR_R_MALLOC_FAILURE);
      goto err;
    }
  }

  if (in_len != rsa_size) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_LEN_NOT_EQUAL_TO_MOD_LEN);
    goto err;
  }

  if (!RSA_private_transform(rsa, buf, in, rsa_size)) {
    goto err;
  }

  switch (padding) {
    case RSA_PKCS1_PADDING:
      r = RSA_padding_check_PKCS1_type_2(out, rsa_size, buf, rsa_size);
      break;
    case RSA_PKCS1_OAEP_PADDING:
      /* Use the default parameters: SHA-1 for both hashes and no label. */
      r = RSA_padding_check_PKCS1_OAEP_mgf1(out, rsa_size, buf, rsa_size,
                                            NULL, 0, NULL, NULL);
      break;
    case RSA_NO_PADDING:
      r = rsa_size;
      break;
    default:
      OPENSSL_PUT_ERROR(RSA, RSA_R_UNKNOWN_PADDING_TYPE);
      goto err;
  }

  if (r < 0) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_PADDING_CHECK_FAILED);
  } else {
    *out_len = r;
    ret = 1;
  }

err:
  if (padding != RSA_NO_PADDING && buf != NULL) {
    OPENSSL_cleanse(buf, rsa_size);
    OPENSSL_free(buf);
  }

  return ret;
}

const struct rsa_meth_st my_rsa_meth = {
  {
    0 /* references */,
    1 /* is_static */,
  },
  NULL /* app_data */,

  NULL /* init */,
  NULL /*finish*/,

  size,

  NULL /* sign */,
  NULL /* verify */,

  encrypt,
  NULL /*sign_raw*/,
  my_decrypt,
  NULL /*verify_raw*/,

  NULL /*private_transform*/,

  NULL /* mod_exp */,
  NULL /* bn_mod_exp */,

  RSA_FLAG_CACHE_PUBLIC | RSA_FLAG_CACHE_PRIVATE,

  NULL /*keygen*/,
  NULL /*keygen_multiprime*/,
};
