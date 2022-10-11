#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef int64_t DartPort;

typedef bool (*DartPostCObjectFnType)(DartPort port_id, void *message);

typedef struct wire_uint_8_list {
  uint8_t *ptr;
  int32_t len;
} wire_uint_8_list;

typedef struct wire_Config {
  struct wire_uint_8_list *initial_oobis;
} wire_Config;

typedef struct wire_PublicKey {
  int32_t *derivation;
  struct wire_uint_8_list *public_key;
} wire_PublicKey;

typedef struct wire_list_public_key {
  struct wire_PublicKey *ptr;
  int32_t len;
} wire_list_public_key;

typedef struct wire_StringList {
  struct wire_uint_8_list **ptr;
  int32_t len;
} wire_StringList;

typedef struct wire_Signature {
  int32_t *derivation;
  struct wire_uint_8_list *signature;
} wire_Signature;

typedef struct wire_Identifier_Basic {
  struct wire_PublicKey *field0;
} wire_Identifier_Basic;

typedef struct wire_DigestType_Blake3_256 {

} wire_DigestType_Blake3_256;

typedef struct wire_DigestType_SHA3_256 {

} wire_DigestType_SHA3_256;

typedef struct wire_DigestType_SHA2_256 {

} wire_DigestType_SHA2_256;

typedef struct wire_DigestType_Blake3_512 {

} wire_DigestType_Blake3_512;

typedef struct wire_DigestType_SHA3_512 {

} wire_DigestType_SHA3_512;

typedef struct wire_DigestType_Blake2B512 {

} wire_DigestType_Blake2B512;

typedef struct wire_DigestType_SHA2_512 {

} wire_DigestType_SHA2_512;

typedef struct wire_DigestType_Blake2B256 {
  struct wire_uint_8_list *field0;
} wire_DigestType_Blake2B256;

typedef struct wire_DigestType_Blake2S256 {
  struct wire_uint_8_list *field0;
} wire_DigestType_Blake2S256;

typedef union DigestTypeKind {
  struct wire_DigestType_Blake3_256 *Blake3_256;
  struct wire_DigestType_SHA3_256 *SHA3_256;
  struct wire_DigestType_SHA2_256 *SHA2_256;
  struct wire_DigestType_Blake3_512 *Blake3_512;
  struct wire_DigestType_SHA3_512 *SHA3_512;
  struct wire_DigestType_Blake2B512 *Blake2B512;
  struct wire_DigestType_SHA2_512 *SHA2_512;
  struct wire_DigestType_Blake2B256 *Blake2B256;
  struct wire_DigestType_Blake2S256 *Blake2S256;
} DigestTypeKind;

typedef struct wire_DigestType {
  int32_t tag;
  union DigestTypeKind *kind;
} wire_DigestType;

typedef struct wire_Digest {
  struct wire_DigestType *derivation;
  struct wire_uint_8_list *digest;
} wire_Digest;

typedef struct wire_Identifier_SelfAddressing {
  struct wire_Digest *field0;
} wire_Identifier_SelfAddressing;

typedef struct wire_Identifier_SelfSigning {
  struct wire_Signature *field0;
} wire_Identifier_SelfSigning;

typedef union IdentifierKind {
  struct wire_Identifier_Basic *Basic;
  struct wire_Identifier_SelfAddressing *SelfAddressing;
  struct wire_Identifier_SelfSigning *SelfSigning;
} IdentifierKind;

typedef struct wire_Identifier {
  int32_t tag;
  union IdentifierKind *kind;
} wire_Identifier;

typedef struct wire_list_identifier {
  struct wire_Identifier *ptr;
  int32_t len;
} wire_list_identifier;

typedef struct wire_DataAndSignature {
  struct wire_uint_8_list *data;
  struct wire_Signature *signature;
} wire_DataAndSignature;

typedef struct wire_list_data_and_signature {
  struct wire_DataAndSignature *ptr;
  int32_t len;
} wire_list_data_and_signature;

typedef struct WireSyncReturnStruct {
  uint8_t *ptr;
  int32_t len;
  bool success;
} WireSyncReturnStruct;

void store_dart_post_cobject(DartPostCObjectFnType ptr);

void wire_with_initial_oobis(int64_t port_,
                             struct wire_Config *config,
                             struct wire_uint_8_list *oobis_json);

void wire_init_kel(int64_t port_,
                   struct wire_uint_8_list *input_app_dir,
                   struct wire_Config *optional_configs);

void wire_incept(int64_t port_,
                 struct wire_list_public_key *public_keys,
                 struct wire_list_public_key *next_pub_keys,
                 struct wire_StringList *witnesses,
                 uint64_t witness_threshold);

void wire_finalize_inception(int64_t port_,
                             struct wire_uint_8_list *event,
                             struct wire_Signature *signature);

void wire_rotate(int64_t port_,
                 struct wire_Identifier *identifier,
                 struct wire_list_public_key *current_keys,
                 struct wire_list_public_key *new_next_keys,
                 struct wire_StringList *witness_to_add,
                 struct wire_StringList *witness_to_remove,
                 uint64_t witness_threshold);

void wire_anchor(int64_t port_,
                 struct wire_Identifier *identifier,
                 struct wire_uint_8_list *data,
                 struct wire_DigestType *algo);

void wire_anchor_digest(int64_t port_,
                        struct wire_Identifier *identifier,
                        struct wire_StringList *sais);

void wire_add_watcher(int64_t port_,
                      struct wire_Identifier *identifier,
                      struct wire_uint_8_list *watcher_oobi);

void wire_finalize_event(int64_t port_,
                         struct wire_Identifier *identifier,
                         struct wire_uint_8_list *event,
                         struct wire_Signature *signature);

void wire_incept_group(int64_t port_,
                       struct wire_Identifier *identifier,
                       struct wire_list_identifier *participants,
                       uint64_t signature_threshold,
                       struct wire_StringList *initial_witnesses,
                       uint64_t witness_threshold);

void wire_finalize_group_incept(int64_t port_,
                                struct wire_Identifier *identifier,
                                struct wire_uint_8_list *group_event,
                                struct wire_Signature *signature,
                                struct wire_list_data_and_signature *to_forward);

void wire_query_mailbox(int64_t port_,
                        struct wire_Identifier *who_ask,
                        struct wire_Identifier *about_who,
                        struct wire_StringList *witness);

void wire_finalize_mailbox_query(int64_t port_,
                                 struct wire_Identifier *identifier,
                                 struct wire_uint_8_list *query_event,
                                 struct wire_Signature *signature);

void wire_resolve_oobi(int64_t port_, struct wire_uint_8_list *oobi_json);

void wire_query(int64_t port_,
                struct wire_Identifier *identifier,
                struct wire_uint_8_list *oobis_json);

void wire_process_stream(int64_t port_, struct wire_uint_8_list *stream);

void wire_get_kel(int64_t port_, struct wire_Identifier *identifier);

void wire_get_current_public_key(int64_t port_, struct wire_uint_8_list *attachment);

void wire_new__static_method__PublicKey(int64_t port_,
                                        int32_t kt,
                                        struct wire_uint_8_list *key_b64);

void wire_new__static_method__Digest(int64_t port_,
                                     struct wire_DigestType *dt,
                                     struct wire_uint_8_list *digest_data);

void wire_new_from_hex__static_method__Signature(int64_t port_,
                                                 int32_t st,
                                                 struct wire_uint_8_list *signature);

void wire_new_from_b64__static_method__Signature(int64_t port_,
                                                 int32_t st,
                                                 struct wire_uint_8_list *signature);

void wire_from_str__static_method__Identifier(int64_t port_, struct wire_uint_8_list *id_str);

void wire_to_str__method__Identifier(int64_t port_, struct wire_Identifier *that);

void wire_new__static_method__DataAndSignature(int64_t port_,
                                               struct wire_uint_8_list *data,
                                               struct wire_Signature *signature);

struct wire_StringList *new_StringList_0(int32_t len);

struct wire_Config *new_box_autoadd_config_0(void);

struct wire_Digest *new_box_autoadd_digest_0(void);

struct wire_DigestType *new_box_autoadd_digest_type_0(void);

struct wire_Identifier *new_box_autoadd_identifier_0(void);

struct wire_PublicKey *new_box_autoadd_public_key_0(void);

struct wire_Signature *new_box_autoadd_signature_0(void);

struct wire_DigestType *new_box_digest_type_0(void);

int32_t *new_box_key_type_0(int32_t value);

struct wire_Signature *new_box_signature_0(void);

int32_t *new_box_signature_type_0(int32_t value);

struct wire_list_data_and_signature *new_list_data_and_signature_0(int32_t len);

struct wire_list_identifier *new_list_identifier_0(int32_t len);

struct wire_list_public_key *new_list_public_key_0(int32_t len);

struct wire_uint_8_list *new_uint_8_list_0(int32_t len);

union DigestTypeKind *inflate_DigestType_Blake2B256(void);

union DigestTypeKind *inflate_DigestType_Blake2S256(void);

union IdentifierKind *inflate_Identifier_Basic(void);

union IdentifierKind *inflate_Identifier_SelfAddressing(void);

union IdentifierKind *inflate_Identifier_SelfSigning(void);

void free_WireSyncReturnStruct(struct WireSyncReturnStruct val);

static int64_t dummy_method_to_enforce_bundling(void) {
    int64_t dummy_var = 0;
    dummy_var ^= ((int64_t) (void*) wire_with_initial_oobis);
    dummy_var ^= ((int64_t) (void*) wire_init_kel);
    dummy_var ^= ((int64_t) (void*) wire_incept);
    dummy_var ^= ((int64_t) (void*) wire_finalize_inception);
    dummy_var ^= ((int64_t) (void*) wire_rotate);
    dummy_var ^= ((int64_t) (void*) wire_anchor);
    dummy_var ^= ((int64_t) (void*) wire_anchor_digest);
    dummy_var ^= ((int64_t) (void*) wire_add_watcher);
    dummy_var ^= ((int64_t) (void*) wire_finalize_event);
    dummy_var ^= ((int64_t) (void*) wire_incept_group);
    dummy_var ^= ((int64_t) (void*) wire_finalize_group_incept);
    dummy_var ^= ((int64_t) (void*) wire_query_mailbox);
    dummy_var ^= ((int64_t) (void*) wire_finalize_mailbox_query);
    dummy_var ^= ((int64_t) (void*) wire_resolve_oobi);
    dummy_var ^= ((int64_t) (void*) wire_query);
    dummy_var ^= ((int64_t) (void*) wire_process_stream);
    dummy_var ^= ((int64_t) (void*) wire_get_kel);
    dummy_var ^= ((int64_t) (void*) wire_get_current_public_key);
    dummy_var ^= ((int64_t) (void*) wire_new__static_method__PublicKey);
    dummy_var ^= ((int64_t) (void*) wire_new__static_method__Digest);
    dummy_var ^= ((int64_t) (void*) wire_new_from_hex__static_method__Signature);
    dummy_var ^= ((int64_t) (void*) wire_new_from_b64__static_method__Signature);
    dummy_var ^= ((int64_t) (void*) wire_from_str__static_method__Identifier);
    dummy_var ^= ((int64_t) (void*) wire_to_str__method__Identifier);
    dummy_var ^= ((int64_t) (void*) wire_new__static_method__DataAndSignature);
    dummy_var ^= ((int64_t) (void*) new_StringList_0);
    dummy_var ^= ((int64_t) (void*) new_box_autoadd_config_0);
    dummy_var ^= ((int64_t) (void*) new_box_autoadd_digest_0);
    dummy_var ^= ((int64_t) (void*) new_box_autoadd_digest_type_0);
    dummy_var ^= ((int64_t) (void*) new_box_autoadd_identifier_0);
    dummy_var ^= ((int64_t) (void*) new_box_autoadd_public_key_0);
    dummy_var ^= ((int64_t) (void*) new_box_autoadd_signature_0);
    dummy_var ^= ((int64_t) (void*) new_box_digest_type_0);
    dummy_var ^= ((int64_t) (void*) new_box_key_type_0);
    dummy_var ^= ((int64_t) (void*) new_box_signature_0);
    dummy_var ^= ((int64_t) (void*) new_box_signature_type_0);
    dummy_var ^= ((int64_t) (void*) new_list_data_and_signature_0);
    dummy_var ^= ((int64_t) (void*) new_list_identifier_0);
    dummy_var ^= ((int64_t) (void*) new_list_public_key_0);
    dummy_var ^= ((int64_t) (void*) new_uint_8_list_0);
    dummy_var ^= ((int64_t) (void*) inflate_DigestType_Blake2B256);
    dummy_var ^= ((int64_t) (void*) inflate_DigestType_Blake2S256);
    dummy_var ^= ((int64_t) (void*) inflate_Identifier_Basic);
    dummy_var ^= ((int64_t) (void*) inflate_Identifier_SelfAddressing);
    dummy_var ^= ((int64_t) (void*) inflate_Identifier_SelfSigning);
    dummy_var ^= ((int64_t) (void*) free_WireSyncReturnStruct);
    dummy_var ^= ((int64_t) (void*) store_dart_post_cobject);
    return dummy_var;
}