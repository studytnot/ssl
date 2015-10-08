/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: tls_message.proto */

#ifndef PROTOBUF_C_tls_5fmessage_2eproto__INCLUDED
#define PROTOBUF_C_tls_5fmessage_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1001001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct _TlsMessage TlsMessage;
typedef struct _RsaDecReq RsaDecReq;


/* --- enums --- */


/* --- messages --- */

struct  _TlsMessage
{
  ProtobufCMessage base;
  protobuf_c_boolean has_version;
  int32_t version;
  protobuf_c_boolean has_id;
  int32_t id;
  char *private_key;
  char *encryt_txt;
};
#define TLS_MESSAGE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&tls_message__descriptor) \
    , 0,0, 0,0, NULL, NULL }


struct  _RsaDecReq
{
  ProtobufCMessage base;
  protobuf_c_boolean has_id;
  int32_t id;
  protobuf_c_boolean has_version;
  int32_t version;
  protobuf_c_boolean has_type;
  int32_t type;
  protobuf_c_boolean has_out_len;
  int32_t out_len;
  protobuf_c_boolean has_in_len;
  int32_t in_len;
  protobuf_c_boolean has_max_out;
  int32_t max_out;
  protobuf_c_boolean has_padding;
  int32_t padding;
  char *public_key;
  char *private_key;
  char *encrypt_txt;
  char *decrypt_txt;
};
#define RSA_DEC_REQ__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&rsa_dec_req__descriptor) \
    , 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, NULL, NULL, NULL, NULL }


/* TlsMessage methods */
void   tls_message__init
                     (TlsMessage         *message);
size_t tls_message__get_packed_size
                     (const TlsMessage   *message);
size_t tls_message__pack
                     (const TlsMessage   *message,
                      uint8_t             *out);
size_t tls_message__pack_to_buffer
                     (const TlsMessage   *message,
                      ProtobufCBuffer     *buffer);
TlsMessage *
       tls_message__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   tls_message__free_unpacked
                     (TlsMessage *message,
                      ProtobufCAllocator *allocator);
/* RsaDecReq methods */
void   rsa_dec_req__init
                     (RsaDecReq         *message);
size_t rsa_dec_req__get_packed_size
                     (const RsaDecReq   *message);
size_t rsa_dec_req__pack
                     (const RsaDecReq   *message,
                      uint8_t             *out);
size_t rsa_dec_req__pack_to_buffer
                     (const RsaDecReq   *message,
                      ProtobufCBuffer     *buffer);
RsaDecReq *
       rsa_dec_req__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   rsa_dec_req__free_unpacked
                     (RsaDecReq *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*TlsMessage_Closure)
                 (const TlsMessage *message,
                  void *closure_data);
typedef void (*RsaDecReq_Closure)
                 (const RsaDecReq *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor tls_message__descriptor;
extern const ProtobufCMessageDescriptor rsa_dec_req__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_tls_5fmessage_2eproto__INCLUDED */
