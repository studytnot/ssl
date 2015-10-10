#include <openssl/rsa.h>

#include <string.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include "openssl/mem.h"
#include <openssl/thread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "crypto/rsa/internal.h"
#include "crypto/internal.h"
#include "my_engine.h"
#include "tls_message.pb-c.h"

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

static int my_encrypt(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
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
  printf("after my bn_mod_exp\n");

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

static int send_pb(uint8_t *buf, int len) {
    int sock_fd = 0, n = 0;
    struct sockaddr_in serv_addr;

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
         printf("fail to create socket\n");
         return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port   = htons(10001);
    if ((inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)) < 0) {
        printf("fail to inet_pton\n");
        return -1;
    }

    if (connect(sock_fd, (const struct sockaddr*) &serv_addr, sizeof(serv_addr)) < 0) {
         printf("fail to connect \n");
         return -1;
    }

    n = write(sock_fd, buf, len);
    printf("suc to send:%d bytes\n", n);

    return n;
}

static int my_decrypt(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                   const uint8_t *in, size_t in_len, int padding) {
  const unsigned rsa_size = RSA_size(rsa);
  int r = -1;
  uint8_t *buf = NULL;
  int ret = 0;

  printf("my decrypt, file:%s line:%d \n", __FILE__, __LINE__);

  if (max_out < rsa_size) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_OUTPUT_BUFFER_TOO_SMALL);
    return 0;
  }


  RsaDecReq req = RSA_DEC_REQ__INIT;
  req.has_id = 1;
  req.id        = 18;
  req.version   = 2;
  req.has_version = 1;
  req.max_out   = 13;
  req.has_max_out = 1;
  req.out_len   = *out_len;
  req.has_out_len = 1;
  req.padding   = 11;
  req.has_padding = 1;
  unsigned char *key_buf = NULL;
  printf("hi, file:%s line:%d\n", __FILE__, __LINE__);
  int key_len  =  i2d_RSAPrivateKey(rsa, (uint8_t **) &key_buf);
  printf("hi, file:%s line:%d\n", __FILE__, __LINE__);
  req.private_key.data = (uint8_t *)malloc(key_len);
  req.private_key.len  = key_len;
  req.encrypt_txt.data = (uint8_t *)malloc(in_len);
  req.encrypt_txt.len  = in_len;
  memcpy(req.private_key.data, key_buf, key_len);
  memcpy(req.encrypt_txt.data, in, in_len);
  printf("memcpy to req.private_key, key_len:%d\n", key_len);
  printf("i2d_rsaprivatekey len:%d max_out:%d padding:%d id:%d\n", key_len, req.max_out, req.padding, req.id);
  printf("key buf:\n");
  req.private_key_len = key_len;
  req.has_private_key_len = 1;
  print_hex(key_buf, key_len);
  printf("private key\n");
  print_hex(req.private_key.data, key_len);
  req.has_private_key = 1;
  req.has_encrypt_txt = 1;
  printf("hi, private key len:%d file:%s line:%d\n", req.private_key_len,  __FILE__, __LINE__);

  printf("encrypt txt:\n");
  print_hex(req.encrypt_txt.data, in_len);

  int pack_size = rsa_dec_req__get_packed_size(&req);
  printf("packed size:%d\n", pack_size);
  void *pb_buf = malloc(pack_size);
  rsa_dec_req__pack(&req, pb_buf);

  send_pb(pb_buf, pack_size);

  sleep(1);
  printf("hi file:%s line:%d\n", __FILE__, __LINE__);
  RsaDecReq *re = rsa_dec_req__unpack(NULL, pack_size, pb_buf);
  printf("hi file:%s line:%d\n", __FILE__, __LINE__);
  if (re->private_key.data == NULL) {
      printf("fail to get private data\n");
      return -1;
  }
  print_hex(re->private_key.data, key_len);
  printf("hi file:%s line:%d\n", __FILE__, __LINE__);

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

  printf("my decrypt, file:%s line:%d \n", __FILE__, __LINE__);
  if (!RSA_private_transform(rsa, buf, in, rsa_size)) {
    goto err;
  }
  printf("my decrypt, file:%s line:%d \n", __FILE__, __LINE__);

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
  printf("my decrypt, file:%s line:%d \n", __FILE__, __LINE__);

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

static int mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx) {
  BIGNUM *r1, *m1, *vrfy;
  BIGNUM local_dmp1, local_dmq1, local_c, local_r1;
  BIGNUM *dmp1, *dmq1, *c, *pr1;
  int ret = 0;
  size_t i, num_additional_primes = 0;

  if (rsa->additional_primes != NULL) {
    num_additional_primes = sk_RSA_additional_prime_num(rsa->additional_primes);
  }

  BN_CTX_start(ctx);
  r1 = BN_CTX_get(ctx);
  m1 = BN_CTX_get(ctx);
  vrfy = BN_CTX_get(ctx);

  {
    BIGNUM local_p, local_q;
    BIGNUM *p = NULL, *q = NULL;

    /* Make sure BN_mod_inverse in Montgomery intialization uses the
     * BN_FLG_CONSTTIME flag (unless RSA_FLAG_NO_CONSTTIME is set) */
    BN_init(&local_p);
    p = &local_p;
    BN_with_flags(p, rsa->p, BN_FLG_CONSTTIME);

    BN_init(&local_q);
    q = &local_q;
    BN_with_flags(q, rsa->q, BN_FLG_CONSTTIME);

    if (rsa->flags & RSA_FLAG_CACHE_PRIVATE) {
      if (BN_MONT_CTX_set_locked(&rsa->_method_mod_p, &rsa->lock, p, ctx) ==
          NULL) {
        goto err;
      }
      if (BN_MONT_CTX_set_locked(&rsa->_method_mod_q, &rsa->lock, q, ctx) ==
          NULL) {
        goto err;
      }
    }
  }

  if (rsa->flags & RSA_FLAG_CACHE_PUBLIC) {
    if (BN_MONT_CTX_set_locked(&rsa->_method_mod_n, &rsa->lock, rsa->n, ctx) ==
        NULL) {
      goto err;
    }
  }

  /* compute I mod q */
  c = &local_c;
  BN_with_flags(c, I, BN_FLG_CONSTTIME);
  if (!BN_mod(r1, c, rsa->q, ctx)) {
    goto err;
  }

  /* compute r1^dmq1 mod q */
  dmq1 = &local_dmq1;
  BN_with_flags(dmq1, rsa->dmq1, BN_FLG_CONSTTIME);
  if (!rsa->meth->bn_mod_exp(m1, r1, dmq1, rsa->q, ctx, rsa->_method_mod_q)) {
    goto err;
  }

  /* compute I mod p */
  c = &local_c;
  BN_with_flags(c, I, BN_FLG_CONSTTIME);
  if (!BN_mod(r1, c, rsa->p, ctx)) {
    goto err;
  }

  /* compute r1^dmp1 mod p */
  dmp1 = &local_dmp1;
  BN_with_flags(dmp1, rsa->dmp1, BN_FLG_CONSTTIME);
  if (!rsa->meth->bn_mod_exp(r0, r1, dmp1, rsa->p, ctx, rsa->_method_mod_p)) {
    goto err;
  }

  if (!BN_sub(r0, r0, m1)) {
    goto err;
  }
  /* This will help stop the size of r0 increasing, which does
   * affect the multiply if it optimised for a power of 2 size */
  if (BN_is_negative(r0)) {
    if (!BN_add(r0, r0, rsa->p)) {
      goto err;
    }
  }

  if (!BN_mul(r1, r0, rsa->iqmp, ctx)) {
    goto err;
  }

  /* Turn BN_FLG_CONSTTIME flag on before division operation */
  pr1 = &local_r1;
  BN_with_flags(pr1, r1, BN_FLG_CONSTTIME);

  if (!BN_mod(r0, pr1, rsa->p, ctx)) {
    goto err;
  }

  /* If p < q it is occasionally possible for the correction of
   * adding 'p' if r0 is negative above to leave the result still
   * negative. This can break the private key operations: the following
   * second correction should *always* correct this rare occurrence.
   * This will *never* happen with OpenSSL generated keys because
   * they ensure p > q [steve] */
  if (BN_is_negative(r0)) {
    if (!BN_add(r0, r0, rsa->p)) {
      goto err;
    }
  }
  if (!BN_mul(r1, r0, rsa->q, ctx)) {
    goto err;
  }
  if (!BN_add(r0, r1, m1)) {
    goto err;
  }

  for (i = 0; i < num_additional_primes; i++) {
    /* multi-prime RSA. */
    BIGNUM local_exp, local_prime;
    BIGNUM *exp = &local_exp, *prime = &local_prime;
    RSA_additional_prime *ap =
        sk_RSA_additional_prime_value(rsa->additional_primes, i);

    BN_with_flags(exp, ap->exp, BN_FLG_CONSTTIME);
    BN_with_flags(prime, ap->prime, BN_FLG_CONSTTIME);

    /* c will already point to a BIGNUM with the correct flags. */
    if (!BN_mod(r1, c, prime, ctx)) {
      goto err;
    }

    if ((rsa->flags & RSA_FLAG_CACHE_PRIVATE) &&
        !BN_MONT_CTX_set_locked(&ap->method_mod, &rsa->lock, prime, ctx)) {
      goto err;
    }

    if (!rsa->meth->bn_mod_exp(m1, r1, exp, prime, ctx, ap->method_mod)) {
      goto err;
    }

    BN_set_flags(m1, BN_FLG_CONSTTIME);

    if (!BN_sub(m1, m1, r0) ||
        !BN_mul(m1, m1, ap->coeff, ctx) ||
        !BN_mod(m1, m1, prime, ctx) ||
        (BN_is_negative(m1) && !BN_add(m1, m1, prime)) ||
        !BN_mul(m1, m1, ap->r, ctx) ||
        !BN_add(r0, r0, m1)) {
      goto err;
    }
  }

  if (rsa->e && rsa->n) {
    if (!rsa->meth->bn_mod_exp(vrfy, r0, rsa->e, rsa->n, ctx,
                               rsa->_method_mod_n)) {
      goto err;
    }
    /* If 'I' was greater than (or equal to) rsa->n, the operation
     * will be equivalent to using 'I mod n'. However, the result of
     * the verify will *always* be less than 'n' so we don't check
     * for absolute equality, just congruency. */
    if (!BN_sub(vrfy, vrfy, I)) {
      goto err;
    }
    if (!BN_mod(vrfy, vrfy, rsa->n, ctx)) {
      goto err;
    }
    if (BN_is_negative(vrfy)) {
      if (!BN_add(vrfy, vrfy, rsa->n)) {
        goto err;
      }
    }
    if (!BN_is_zero(vrfy)) {
      /* 'I' and 'vrfy' aren't congruent mod n. Don't leak
       * miscalculated CRT output, just do a raw (slower)
       * mod_exp and return that instead. */

      BIGNUM local_d;
      BIGNUM *d = NULL;

      d = &local_d;
      BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);
      if (!rsa->meth->bn_mod_exp(r0, I, d, rsa->n, ctx, rsa->_method_mod_n)) {
        goto err;
      }
    }
  }
  ret = 1;

err:
  BN_CTX_end(ctx);
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

  my_encrypt /*encrypt*/,
  NULL /*sign_raw*/,
  my_decrypt,
  NULL /*verify_raw*/,

  NULL /*private_transform*/,

  mod_exp /* mod_exp */,
  BN_mod_exp_mont /* bn_mod_exp */,

  RSA_FLAG_CACHE_PUBLIC | RSA_FLAG_CACHE_PRIVATE,

  NULL /*keygen*/,
  NULL /*keygen_multiprime*/,
};
