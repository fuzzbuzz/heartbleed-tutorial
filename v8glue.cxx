#include <cstdint>
#include <iostream>
#include <string>

#ifdef USING_BEX
#include "bex.hxx"
#else
#include <node.h>
#endif

#include "coverage.h"

// Declare these externs as returning void, so we don't have to deal
// with includes yet.

extern "C" void
	X509V3_EXT_add_alias(int, int);

extern "C" void
	OBJ_NAME_remove(const char *, int);

extern "C" void
	X509_PURPOSE_get_by_sname(char *);

extern "C" void
	OBJ_NAME_add(const char *, int, const char *);

extern "C" void
	make_revocation_str(int, char *);

extern "C" void
	SSL_load_client_CA_file(const char *);

extern "C" void
	CONF_modules_load_file(const char *, const char *, unsigned long);

extern "C" void
	ASN1_tag2str(int);

extern "C" void
	app_isdir(const char *);

extern "C" void
	check_defer(int);

extern "C" void
	str2fmt(char *);

extern "C" void
	BN_num_bits_word(unsigned long);

extern "C" void
	EVP_PKEY_asn1_new(int, int, const char *, const char *);

extern "C" void
	BN_get_params(int);

extern "C" void
	CRYPTO_malloc(int, const char *, int);

extern "C" void
	EVP_PKEY_meth_new(int, int);

extern "C" void
	EVP_PKEY_meth_find(int);

extern "C" void
	CRYPTO_get_new_lockid(char *);

extern "C" void
	ssl2_get_cipher(unsigned int);

extern "C" void
	X509_TRUST_get0(int);

extern "C" void
	EVP_PKEY_type(int);

extern "C" void
	BUF_strlcat(char *, const char *, unsigned long);

extern "C" void
	dtls1_get_cipher(unsigned int);

extern "C" void
	CRYPTO_destroy_dynlockid(int);

extern "C" void
	ssl3_alert_code(int);

extern "C" void
	ssl3_get_cipher(unsigned int);

extern "C" void
	ERR_set_error_data(char *, int);

extern "C" void
	lh_strhash(const char *);

extern "C" void
	OBJ_NAME_cleanup(int);

extern "C" void
	ERR_error_string(unsigned long, char *);

extern "C" void
	parse_yesno(const char *, int);

extern "C" void
	BIO_new_file(const char *, const char *);

extern "C" void
	EVP_PKEY_asn1_get0(int);

extern "C" void
	ASN1_STRING_TABLE_get(int);

extern "C" void
	pem_check_suffix(const char *, const char *);

extern "C" void
	ERR_remove_state(unsigned long);

extern "C" void
	UI_create_method(char *);

extern "C" void
	OBJ_nid2obj(int);

extern "C" void
	SSL_alert_type_string_long(int);

extern "C" void
	CRYPTO_set_mem_debug_options(long);

extern "C" void
	OBJ_sn2nid(const char *);

extern "C" void
	RAND_egd_bytes(const char *, int);

extern "C" void
	BIO_sock_non_fatal_error(int);

extern "C" void
	OpenSSLDie(const char *, int, const char *);

extern "C" void
	EC_KEY_new_by_curve_name(int);

extern "C" void
	ssl_bad_method(int);

extern "C" void
	BUF_strdup(const char *);

extern "C" void
	EC_GROUP_new_by_curve_name(int);

extern "C" void
	ERR_reason_error_string(unsigned long);

extern "C" void
	tls12_get_hash(unsigned char);

extern "C" void
	dtls1_get_queue_priority(unsigned short, int);

extern "C" void
	CRYPTO_get_dynlock_value(int);

extern "C" void
	tls1_alert_code(int);

extern "C" void
	BUF_strlcpy(char *, const char *, unsigned long);

extern "C" void
	X509_VERIFY_PARAM_lookup(const char *);

extern "C" void
	X509_PURPOSE_get_by_id(int);

extern "C" void
	ENGINE_get_digest_engine(int);

extern "C" void
	X509V3_EXT_get_nid(int);

extern "C" void
	CRYPTO_push_info_(const char *, const char *, int);

extern "C" void
	DSO_global_lookup(const char *);

extern "C" void
	SRP_get_default_gN(const char *);

extern "C" void
	ENGINE_get_pkey_meth_engine(int);

extern "C" void
	CRYPTO_get_lock_name(int);

extern "C" void
	SSL_alert_desc_string(int);

extern "C" void
	a2i_IPADDRESS(const char *);

extern "C" void
	EVP_set_pw_prompt(const char *);

extern "C" void
	rotate_serial(char *, char *, char *);

extern "C" void
	EVP_read_pw_string(char *, int, const char *, int);

extern "C" void
	EVP_get_digestbyname(const char *);

extern "C" void
	OBJ_new_nid(int);

extern "C" void
	RAND_egd(const char *);

extern "C" void
	ERR_func_error_string(unsigned long);

extern "C" void
	OBJ_nid2sn(int);

extern "C" void
	ERR_error_string_n(unsigned long, char *, unsigned long);

extern "C" void
	a2i_IPADDRESS_NC(const char *);

extern "C" void
	CRYPTO_dbg_set_options(long);

extern "C" void
	app_init(long);

extern "C" void
	bn_div_words(unsigned long, unsigned long, unsigned long);

extern "C" void
	CRYPTO_strdup(const char *, const char *, int);

extern "C" void
	EVP_PKEY_asn1_add_alias(int, int);

extern "C" void
	CRYPTO_malloc_locked(int, const char *, int);

extern "C" void
	EVP_read_pw_string_min(char *, int, int, const char *, int);

extern "C" void
	rotate_index(const char *, const char *, const char *);

extern "C" void
	app_tminterval(int, int);

extern "C" void
	PEM_proc_type(char *, int);

extern "C" void
	ENGINE_set_table_flags(unsigned int);

extern "C" void
	ASN1_STRING_type_new(int);

extern "C" void
	ENGINE_get_cipher_engine(int);

extern "C" void
	X509_TRUST_get_by_id(int);

extern "C" void
	RSA_X931_hash_id(int);

extern "C" void
	SRP_VBASE_new(char *);

extern "C" void
	OBJ_txt2nid(const char *);

extern "C" void
	BIO_sock_should_retry(int);

extern "C" void
	app_RAND_load_files(char *);

extern "C" void
	X509_PURPOSE_get0(int);

extern "C" void
	CRYPTO_lock(int, int, const char *, int);

extern "C" void
	ENGINE_get_pkey_asn1_meth_engine(int);

extern "C" void
	X509_REQ_extension_nid(int);

extern "C" void
	ASN1_STRING_TABLE_add(int, long, long, unsigned long, unsigned long);

extern "C" void
	ERR_lib_error_string(unsigned long);

extern "C" void
	OBJ_add_sigid(int, int, int);

extern "C" void
	CONF_modules_unload(int);

extern "C" void
	ASN1_object_size(int, int, int);

extern "C" void
	parse_name(char *, long, int);

extern "C" void
	PEM_dek_info(char *, const char *, int, char *);

extern "C" void
	ASN1_STRING_set_default_mask(unsigned long);

extern "C" void
	name_cmp(const char *, const char *);

extern "C" void
	OBJ_NAME_get(const char *, int);

extern "C" void
	BN_set_params(int, int, int, int);

extern "C" void
	ASN1_tag2bit(int);

extern "C" void
	ssl23_get_cipher(unsigned int);

extern "C" void
	tls1_ec_nid2curve_id(int);

extern "C" void
	SSL_alert_type_string(int);

extern "C" void
	BUF_strndup(const char *, unsigned long);

extern "C" void
	X509V3_parse_list(const char *);

extern "C" void
	OBJ_txt2obj(const char *, int);

extern "C" void
	tls1_ec_curve_id2nid(int);

extern "C" void
	SSL_alert_desc_string_long(int);

extern "C" void
	OBJ_create(const char *, const char *, const char *);

extern "C" void
	program_name(char *, char *, int);

extern "C" void
	FuzzerEntrypoint(const unsigned char *, unsigned long);

extern "C" void
	ASN1_STRING_set_default_mask_asc(const char *);

extern "C" void
	ERR_put_error(int, int, int, const char *, int);

extern "C" void
	OBJ_ln2nid(const char *);

extern "C" void
	ssl_verify_alarm_type(long);

extern "C" void
	CRYPTO_mem_ctrl(int);

extern "C" void
	EVP_get_cipherbyname(const char *);

extern "C" void
	OBJ_nid2ln(int);

extern "C" void
	BIO_new_socket(int, int);

extern "C" void
	ENGINE_by_id(const char *);


namespace v8glue
{

using v8::FunctionCallbackInfo;
using v8::Local;
using v8::Object;
using v8::Value;


inline void _excMsg(v8::Isolate *isolate, const char *msg)
{
#if V8_MAJOR_VERSION < 8
	isolate->ThrowException(v8::String::NewFromUtf8(isolate, msg));
#else
	isolate->ThrowException(v8::String::NewFromUtf8(isolate, msg).ToLocalChecked());
#endif
}

inline void _excTypeNotA(v8::Isolate *isolate, int pos, const char *typeName)
{
	std::string s("arg " + std::to_string(pos) + " isn't a " + typeName);
	_excMsg(isolate, s.c_str());
}

inline void _excVectorNotFilled(v8::Isolate *isolate, int expected, int actual)
{
	std::string s("Failed to copy all data to vector. "
                  "Bytes Expected: " + std::to_string(expected) +
                  "Bytes Copied: " + std::to_string(actual));
	_excMsg(isolate, s.c_str());
}

template <class T>
bool FromBigInt(const FunctionCallbackInfo<Value> &args, int pos, T &v)
{
	v8::Isolate *isolate = args.GetIsolate();
	Local<Value> arg = args[pos];

	if (!arg->IsBigInt()) {
		_excTypeNotA(isolate, pos, "BigInt");
		return false;
	}

	v8::Local<v8::BigInt> t = v8::Local<v8::BigInt>::Cast(arg);
	v = t->Uint64Value();

	return true;
}

template <class T>
bool Fromstring(const FunctionCallbackInfo<Value> &args, int pos, T &v)
{
	v8::Isolate *isolate = args.GetIsolate();
	Local<Value> arg = args[pos];

	if (!arg->IsString()) {
		_excTypeNotA(isolate, pos, "string");
		return false;
	}

	v8::String::Utf8Value s(isolate, arg);
	v = *s;

	return true;
}

template <class T>
bool FromNumber(const FunctionCallbackInfo<Value> &args, int pos, T &v)
{
	v8::Isolate *isolate = args.GetIsolate();
	Local<Value> arg = args[pos];

	if (!arg->IsNumber()) {
		_excTypeNotA(isolate, pos, "Number");
		return false;
	}

	v8::Local<v8::Number> t = v8::Local<v8::Number>::Cast(arg);
	v = t->Value();

	return true;
}


// int X509V3_EXT_add_alias(int, int)
void Ff5c353af12e050f9b075655f13344c90cfbfb835(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 2) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	
	   
        int arg1;

	if (!FromBigInt(args, 1, arg1)) {
                return;
        }


	

	X509V3_EXT_add_alias(arg0,arg1);
}

// int OBJ_NAME_remove(const char *, int)
void Fbdde52fc0aa3122703e226e66355688b4eba7376(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 2) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg1;

	if (!FromBigInt(args, 1, arg1)) {
                return;
        }


	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	

	OBJ_NAME_remove(arg0,arg1);
}

// int X509_PURPOSE_get_by_sname(char *)
void Ff6e9941f5fdf360fc1fc2e9410a72bb53cb23bc3(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (char *)arg0container.c_str();


	

	X509_PURPOSE_get_by_sname(arg0);
}

// int OBJ_NAME_add(const char *, int, const char *)
void F6540b5cec98edbaa65a07f5435a2f19792cdf4ef(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 3) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg1;

	if (!FromBigInt(args, 1, arg1)) {
                return;
        }


	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	
	   
        const char * arg2;

        std::string arg2container;
        if (!Fromstring(args, 2, arg2container)) {
                return;
        }

	arg2 = (const char *)arg2container.c_str();


	

	OBJ_NAME_add(arg0,arg1,arg2);
}

// char *make_revocation_str(int, char *)
void Fab452aae83fdb7543bcdbcce8234adc0869cd97e(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 2) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	
	   
        char * arg1;

        std::string arg1container;
        if (!Fromstring(args, 1, arg1container)) {
                return;
        }

	arg1 = (char *)arg1container.c_str();


	

	make_revocation_str(arg0,arg1);
}

// struct stack_st_X509_NAME *SSL_load_client_CA_file(const char *)
void F5c9f55f0750024d45ac6dd88f01add42be330ff0(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	

	SSL_load_client_CA_file(arg0);
}

// int CONF_modules_load_file(const char *, const char *, unsigned long)
void Fa561a51799a68a95f687e8189e1f15f5319834ea(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 3) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        unsigned long arg2;

	if (!FromBigInt(args, 2, arg2)) {
                return;
        }


	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	
	   
        const char * arg1;

        std::string arg1container;
        if (!Fromstring(args, 1, arg1container)) {
                return;
        }

	arg1 = (const char *)arg1container.c_str();


	

	CONF_modules_load_file(arg0,arg1,arg2);
}

// const char *ASN1_tag2str(int)
void F22354db8a27cb2263d0a119c7d9c88cf86442fe9(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	ASN1_tag2str(arg0);
}

// int app_isdir(const char *)
void F91aa3575215ce93743ed6c84f693423850887d8b(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	

	app_isdir(arg0);
}

// void check_defer(int)
void F967eb4e00b6b220c4986e65dd50c8d6746dfc586(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	check_defer(arg0);
}

// int str2fmt(char *)
void F91dd22988f5e3fe5d6b7f474d898b6679d55382a(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (char *)arg0container.c_str();


	

	str2fmt(arg0);
}

// int BN_num_bits_word(unsigned long)
void Fe9c2e889e8cb007b9397686f9ddf68fbb432ded7(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        unsigned long arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	BN_num_bits_word(arg0);
}

// struct evp_pkey_asn1_method_st *EVP_PKEY_asn1_new(int, int, const char *, const char *)
void Fd99514fde33712a8cafc36f61288dcb9d2979600(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 4) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	
	   
        int arg1;

	if (!FromBigInt(args, 1, arg1)) {
                return;
        }


	
	   
        const char * arg2;

        std::string arg2container;
        if (!Fromstring(args, 2, arg2container)) {
                return;
        }

	arg2 = (const char *)arg2container.c_str();


	
	   
        const char * arg3;

        std::string arg3container;
        if (!Fromstring(args, 3, arg3container)) {
                return;
        }

	arg3 = (const char *)arg3container.c_str();


	

	EVP_PKEY_asn1_new(arg0,arg1,arg2,arg3);
}

// int BN_get_params(int)
void F03570939aff17c4c5b100ca90efd3546d24ec2e5(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	BN_get_params(arg0);
}

// void *CRYPTO_malloc(int, const char *, int)
void F3f891508b4018fdbdc77c5a8a94b52efa6c44866(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 3) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	
	   
        int arg2;

	if (!FromBigInt(args, 2, arg2)) {
                return;
        }


	
	   
        const char * arg1;

        std::string arg1container;
        if (!Fromstring(args, 1, arg1container)) {
                return;
        }

	arg1 = (const char *)arg1container.c_str();


	

	CRYPTO_malloc(arg0,arg1,arg2);
}

// struct evp_pkey_method_st *EVP_PKEY_meth_new(int, int)
void F9007108531962d8f270c746313eaa03b341109ea(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 2) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	
	   
        int arg1;

	if (!FromBigInt(args, 1, arg1)) {
                return;
        }


	

	EVP_PKEY_meth_new(arg0,arg1);
}

// const struct evp_pkey_method_st *EVP_PKEY_meth_find(int)
void Fe97ff9adb5bfb7bb500c2224d30832aab6fffabd(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	EVP_PKEY_meth_find(arg0);
}

// int CRYPTO_get_new_lockid(char *)
void F98402ab8e1e9be0331fe309fc933b90a712de7be(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (char *)arg0container.c_str();


	

	CRYPTO_get_new_lockid(arg0);
}

// const struct ssl_cipher_st *ssl2_get_cipher(unsigned int)
void Fe8a6e624890d1d016813ea8da358c65e00d095b4(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        unsigned int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	ssl2_get_cipher(arg0);
}

// struct x509_trust_st *X509_TRUST_get0(int)
void F04ac48616804a41d5cf31f9d5b1f4c69d66b7cab(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	X509_TRUST_get0(arg0);
}

// int EVP_PKEY_type(int)
void Feab34d6bd1e1908270a948da4619c990a70b637f(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	EVP_PKEY_type(arg0);
}

// unsigned long BUF_strlcat(char *, const char *, unsigned long)
void F35b2579c7dc1055c655c2cd192ba9d74637eead7(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 3) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
#if V8_MAJOR_VERSION < 8
	v8::ArrayBuffer::Contents arg1;
#else
	std::shared_ptr<v8::BackingStore> arg1;
#endif
	{
		Local<Value> arg = args[1];
		if (!arg->IsArrayBufferView()) {
			_excTypeNotA(isolate, 1, "array buffer view");
			return;
		}

		Local<v8::ArrayBufferView> view =
		    v8::Local<v8::ArrayBufferView>::Cast(arg);

#if V8_MAJOR_VERSION < 8
		arg1 = view->Buffer()->GetContents();
#else
		arg1 = view->Buffer()->GetBackingStore();
#endif
	}

	
	   
        char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (char *)arg0container.c_str();


	

	BUF_strlcat(arg0,
#if V8_MAJOR_VERSION < 8
	(const char *)arg1.Data()
#else
	(const char *)arg1->Data()
#endif
,
#if V8_MAJOR_VERSION < 8
	(unsigned long)arg1.ByteLength()
#else
	(unsigned long)arg1->ByteLength()
#endif
);
}

// const struct ssl_cipher_st *dtls1_get_cipher(unsigned int)
void F178db9e12c3140d00dddd2e60fc5d17b9a15e50d(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        unsigned int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	dtls1_get_cipher(arg0);
}

// void CRYPTO_destroy_dynlockid(int)
void F96ce81ead890005724e32baeb740fbf1e72491e7(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	CRYPTO_destroy_dynlockid(arg0);
}

// int ssl3_alert_code(int)
void Fcd5bbec33510a2bb830434212b280b3a8eba747f(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	ssl3_alert_code(arg0);
}

// const struct ssl_cipher_st *ssl3_get_cipher(unsigned int)
void Fd377300718c7787d1951b8305c6b43dab0e55d1a(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        unsigned int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	ssl3_get_cipher(arg0);
}

// void ERR_set_error_data(char *, int)
void Fbca24acef13389fa41f1e6f994b2e5a5593313c1(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 2) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg1;

	if (!FromBigInt(args, 1, arg1)) {
                return;
        }


	
	   
        char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (char *)arg0container.c_str();


	

	ERR_set_error_data(arg0,arg1);
}

// unsigned long lh_strhash(const char *)
void F00870b23e2f1aa2d60f1077afe068779905a6b7c(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	

	lh_strhash(arg0);
}

// void OBJ_NAME_cleanup(int)
void Fe62a0fb5ea4a4e3d441f82264e8f419b64f83df1(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	OBJ_NAME_cleanup(arg0);
}

// char *ERR_error_string(unsigned long, char *)
void Fb8320143fb66752b5acf0749720e917aacf0fdae(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 2) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        unsigned long arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	
	   
        char * arg1;

        std::string arg1container;
        if (!Fromstring(args, 1, arg1container)) {
                return;
        }

	arg1 = (char *)arg1container.c_str();


	

	ERR_error_string(arg0,arg1);
}

// int parse_yesno(const char *, int)
void F0343cc72d1404268343721d3f392bf214d3b2d97(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 2) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg1;

	if (!FromBigInt(args, 1, arg1)) {
                return;
        }


	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	

	parse_yesno(arg0,arg1);
}

// struct bio_st *BIO_new_file(const char *, const char *)
void F04b160c04b6b047e2c95ae53e03f14237bf56cc1(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 2) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	
	   
        const char * arg1;

        std::string arg1container;
        if (!Fromstring(args, 1, arg1container)) {
                return;
        }

	arg1 = (const char *)arg1container.c_str();


	

	BIO_new_file(arg0,arg1);
}

// const struct evp_pkey_asn1_method_st *EVP_PKEY_asn1_get0(int)
void Fc094fb7d243ebfdff2012fb323e0ac1ceb055840(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	EVP_PKEY_asn1_get0(arg0);
}

// struct asn1_string_table_st *ASN1_STRING_TABLE_get(int)
void F45a6c15bf8aebed2bd07660d26d6410f7995cab7(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	ASN1_STRING_TABLE_get(arg0);
}

// int pem_check_suffix(const char *, const char *)
void Fcae7001bca697e1ebc6593e5f07670a4ff0557e9(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 2) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	
	   
        const char * arg1;

        std::string arg1container;
        if (!Fromstring(args, 1, arg1container)) {
                return;
        }

	arg1 = (const char *)arg1container.c_str();


	

	pem_check_suffix(arg0,arg1);
}

// void ERR_remove_state(unsigned long)
void F43e54da7587da68b838b74d471d51027bfc4d9d2(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        unsigned long arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	ERR_remove_state(arg0);
}

// struct ui_method_st *UI_create_method(char *)
void F2905eaf84829553f109d69cd0e8e3cbb3db4a9ad(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (char *)arg0container.c_str();


	

	UI_create_method(arg0);
}

// struct asn1_object_st *OBJ_nid2obj(int)
void F9c15cea8f4734fadc396ec0b90726dea1f149644(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	OBJ_nid2obj(arg0);
}

// const char *SSL_alert_type_string_long(int)
void Fa64c4183ebf34775e342b7db8f185e53224092c9(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	SSL_alert_type_string_long(arg0);
}

// void CRYPTO_set_mem_debug_options(long)
void F076dd4e443ac7604a639be4dcafce7ed8642edfc(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        long arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	CRYPTO_set_mem_debug_options(arg0);
}

// int OBJ_sn2nid(const char *)
void F04ca27d2727d2f59cac0bf37b440d9072fc6b7cc(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	

	OBJ_sn2nid(arg0);
}

// int RAND_egd_bytes(const char *, int)
void Ff5bfae44e404ecab5babcaa9a9868dbf2843a5e3(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 2) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg1;

	if (!FromBigInt(args, 1, arg1)) {
                return;
        }


	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	

	RAND_egd_bytes(arg0,arg1);
}

// int BIO_sock_non_fatal_error(int)
void F28e7ab0aff8acd1488479d8e3d3684a65f3a3e48(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	BIO_sock_non_fatal_error(arg0);
}

// void OpenSSLDie(const char *, int, const char *)
void F300d5d9f4acaa96a3e19b5c5b7cd0751217d8999(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 3) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg1;

	if (!FromBigInt(args, 1, arg1)) {
                return;
        }


	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	
	   
        const char * arg2;

        std::string arg2container;
        if (!Fromstring(args, 2, arg2container)) {
                return;
        }

	arg2 = (const char *)arg2container.c_str();


	

	OpenSSLDie(arg0,arg1,arg2);
}

// struct ec_key_st *EC_KEY_new_by_curve_name(int)
void F6b51b926459b8d06ce56f207d0eac23f1cb48e3f(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	EC_KEY_new_by_curve_name(arg0);
}

// struct ssl_method_st *ssl_bad_method(int)
void F843a70847ed7f94a5050e239388247fe2f51a70e(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	ssl_bad_method(arg0);
}

// char *BUF_strdup(const char *)
void Fb1bd9e6bb5c712af29fb86024e274d36728dde60(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	

	BUF_strdup(arg0);
}

// struct ec_group_st *EC_GROUP_new_by_curve_name(int)
void Fa870d3ec6367b211d530e84081789035e48d9f53(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	EC_GROUP_new_by_curve_name(arg0);
}

// const char *ERR_reason_error_string(unsigned long)
void Faeafccd98c1a29b1a43d7c8263d95a4c09b04bf6(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        unsigned long arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	ERR_reason_error_string(arg0);
}

// const struct env_md_st *tls12_get_hash(unsigned char)
void Ffcb6e9345977648c45c5a9b507cd74bc77095caa(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        unsigned char arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	tls12_get_hash(arg0);
}

// int dtls1_get_queue_priority(unsigned short, int)
void F9a51bb8b7186ea32ad6c2a1a2106107e4c355c0c(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 2) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg1;

	if (!FromBigInt(args, 1, arg1)) {
                return;
        }


	
	   
        unsigned short arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	dtls1_get_queue_priority(arg0,arg1);
}

// struct CRYPTO_dynlock_value *CRYPTO_get_dynlock_value(int)
void Fdd13e1e75414735910056181e4243b15290c2499(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	CRYPTO_get_dynlock_value(arg0);
}

// int tls1_alert_code(int)
void F465d2b978111476900f8a0851870c20ed035a795(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	tls1_alert_code(arg0);
}

// unsigned long BUF_strlcpy(char *, const char *, unsigned long)
void F505571b978dcbfbec6f2cdaeccfec3ef04e1ed49(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 3) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
#if V8_MAJOR_VERSION < 8
	v8::ArrayBuffer::Contents arg1;
#else
	std::shared_ptr<v8::BackingStore> arg1;
#endif
	{
		Local<Value> arg = args[1];
		if (!arg->IsArrayBufferView()) {
			_excTypeNotA(isolate, 1, "array buffer view");
			return;
		}

		Local<v8::ArrayBufferView> view =
		    v8::Local<v8::ArrayBufferView>::Cast(arg);

#if V8_MAJOR_VERSION < 8
		arg1 = view->Buffer()->GetContents();
#else
		arg1 = view->Buffer()->GetBackingStore();
#endif
	}

	
	   
        char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (char *)arg0container.c_str();


	

	BUF_strlcpy(arg0,
#if V8_MAJOR_VERSION < 8
	(const char *)arg1.Data()
#else
	(const char *)arg1->Data()
#endif
,
#if V8_MAJOR_VERSION < 8
	(unsigned long)arg1.ByteLength()
#else
	(unsigned long)arg1->ByteLength()
#endif
);
}

// const struct X509_VERIFY_PARAM_st *X509_VERIFY_PARAM_lookup(const char *)
void Fb818030be70dd7462e11aaf7abc7a28fe1962153(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	

	X509_VERIFY_PARAM_lookup(arg0);
}

// int X509_PURPOSE_get_by_id(int)
void Fd063720e4cb29e6e6794c4d5d367c5bbaa9033d9(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	X509_PURPOSE_get_by_id(arg0);
}

// struct engine_st *ENGINE_get_digest_engine(int)
void Fbdad082abdb69c313ff040a65e4cdb08e3107677(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	ENGINE_get_digest_engine(arg0);
}

// const struct v3_ext_method *X509V3_EXT_get_nid(int)
void F4c5bbe1a85b8b8a9ba3fee167c5678edcc316ffd(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	X509V3_EXT_get_nid(arg0);
}

// int CRYPTO_push_info_(const char *, const char *, int)
void F6c398d138afb6fff67fa2c9182946d3383fb4866(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 3) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg2;

	if (!FromBigInt(args, 2, arg2)) {
                return;
        }


	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	
	   
        const char * arg1;

        std::string arg1container;
        if (!Fromstring(args, 1, arg1container)) {
                return;
        }

	arg1 = (const char *)arg1container.c_str();


	

	CRYPTO_push_info_(arg0,arg1,arg2);
}

// void *DSO_global_lookup(const char *)
void Fd2535c701d4e09f548989a3ef86a6c6f3c03604b(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	

	DSO_global_lookup(arg0);
}

// struct SRP_gN_st *SRP_get_default_gN(const char *)
void F608b32cfaab5c93dc4c7b4954dcc6e85029bd4cf(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	

	SRP_get_default_gN(arg0);
}

// struct engine_st *ENGINE_get_pkey_meth_engine(int)
void Fa7fb86003a76e2553bbe57b40b699db72353a4e3(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	ENGINE_get_pkey_meth_engine(arg0);
}

// const char *CRYPTO_get_lock_name(int)
void F22e38a1127e5dd20729c4c7385dd313a74875195(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	CRYPTO_get_lock_name(arg0);
}

// const char *SSL_alert_desc_string(int)
void F378f1050c368e5bb809952a4babce43fa6ed3fa1(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	SSL_alert_desc_string(arg0);
}

// struct asn1_string_st *a2i_IPADDRESS(const char *)
void Ff6c3c1e8c7585e606feaa1c1ebda69e590491bbd(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	

	a2i_IPADDRESS(arg0);
}

// void EVP_set_pw_prompt(const char *)
void F553e95e7d0d11368328c693892132ed32c6bde8e(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	

	EVP_set_pw_prompt(arg0);
}

// int rotate_serial(char *, char *, char *)
void F3a6de72dc6a9231821fdd1857ef99fe8fc2479e5(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 3) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (char *)arg0container.c_str();


	
	   
        char * arg1;

        std::string arg1container;
        if (!Fromstring(args, 1, arg1container)) {
                return;
        }

	arg1 = (char *)arg1container.c_str();


	
	   
        char * arg2;

        std::string arg2container;
        if (!Fromstring(args, 2, arg2container)) {
                return;
        }

	arg2 = (char *)arg2container.c_str();


	

	rotate_serial(arg0,arg1,arg2);
}

// int EVP_read_pw_string(char *, int, const char *, int)
void Fd6d0e1643d32c580ed02aabfed4eea7a31259821(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 4) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg1;

	if (!FromBigInt(args, 1, arg1)) {
                return;
        }


	
	   
        int arg3;

	if (!FromBigInt(args, 3, arg3)) {
                return;
        }


	
	   
        char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (char *)arg0container.c_str();


	
	   
        const char * arg2;

        std::string arg2container;
        if (!Fromstring(args, 2, arg2container)) {
                return;
        }

	arg2 = (const char *)arg2container.c_str();


	

	EVP_read_pw_string(arg0,arg1,arg2,arg3);
}

// const struct env_md_st *EVP_get_digestbyname(const char *)
void Ff13bbe52960485801a22bca127731aff6571ea00(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	

	EVP_get_digestbyname(arg0);
}

// int OBJ_new_nid(int)
void F5b0f88f7b3515766bc77c5e2b3538917d3ae50ba(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	OBJ_new_nid(arg0);
}

// int RAND_egd(const char *)
void F7741397c54505522901b321d04a0f0181d96bd87(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	

	RAND_egd(arg0);
}

// const char *ERR_func_error_string(unsigned long)
void Fb7fd0942506396403329e499416c8145d21fff8d(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        unsigned long arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	ERR_func_error_string(arg0);
}

// const char *OBJ_nid2sn(int)
void Fdbaa8d10bfcc89f27e7c15dc93e9b2cb148c8a9e(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	OBJ_nid2sn(arg0);
}

// void ERR_error_string_n(unsigned long, char *, unsigned long)
void Feb3e496e35232aeb5b7ead4d6e2fd112e0c8bcb0(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 3) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
#if V8_MAJOR_VERSION < 8
	v8::ArrayBuffer::Contents arg1;
#else
	std::shared_ptr<v8::BackingStore> arg1;
#endif
	{
		Local<Value> arg = args[1];
		if (!arg->IsArrayBufferView()) {
			_excTypeNotA(isolate, 1, "array buffer view");
			return;
		}

		Local<v8::ArrayBufferView> view =
		    v8::Local<v8::ArrayBufferView>::Cast(arg);

#if V8_MAJOR_VERSION < 8
		arg1 = view->Buffer()->GetContents();
#else
		arg1 = view->Buffer()->GetBackingStore();
#endif
	}

	
	   
        unsigned long arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	ERR_error_string_n(arg0,
#if V8_MAJOR_VERSION < 8
	(char *)arg1.Data()
#else
	(char *)arg1->Data()
#endif
,
#if V8_MAJOR_VERSION < 8
	(unsigned long)arg1.ByteLength()
#else
	(unsigned long)arg1->ByteLength()
#endif
);
}

// struct asn1_string_st *a2i_IPADDRESS_NC(const char *)
void F52b8b0b795b676bc9472876c6e75152d885aacdc(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	

	a2i_IPADDRESS_NC(arg0);
}

// void CRYPTO_dbg_set_options(long)
void F82335ac28b86f5ea26de5c171cdd936789beda08(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        long arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	CRYPTO_dbg_set_options(arg0);
}

// int app_init(long)
void F6cef3c719d5773777c1f415016dcb77c817d8e08(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        long arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	app_init(arg0);
}

// unsigned long bn_div_words(unsigned long, unsigned long, unsigned long)
void F18ad0ab09eabd710082995c5427ba3efc36bc21a(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 3) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        unsigned long arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	
	   
        unsigned long arg1;

	if (!FromBigInt(args, 1, arg1)) {
                return;
        }


	
	   
        unsigned long arg2;

	if (!FromBigInt(args, 2, arg2)) {
                return;
        }


	

	bn_div_words(arg0,arg1,arg2);
}

// char *CRYPTO_strdup(const char *, const char *, int)
void Fd6b01b638bdc9193db96414949f5a27d34b814c6(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 3) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg2;

	if (!FromBigInt(args, 2, arg2)) {
                return;
        }


	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	
	   
        const char * arg1;

        std::string arg1container;
        if (!Fromstring(args, 1, arg1container)) {
                return;
        }

	arg1 = (const char *)arg1container.c_str();


	

	CRYPTO_strdup(arg0,arg1,arg2);
}

// int EVP_PKEY_asn1_add_alias(int, int)
void F1375428682ae931890b9506be00b036dd3cd6a9b(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 2) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	
	   
        int arg1;

	if (!FromBigInt(args, 1, arg1)) {
                return;
        }


	

	EVP_PKEY_asn1_add_alias(arg0,arg1);
}

// void *CRYPTO_malloc_locked(int, const char *, int)
void F35210f71d91dd9633ef15f6c0423b32acf77b808(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 3) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	
	   
        int arg2;

	if (!FromBigInt(args, 2, arg2)) {
                return;
        }


	
	   
        const char * arg1;

        std::string arg1container;
        if (!Fromstring(args, 1, arg1container)) {
                return;
        }

	arg1 = (const char *)arg1container.c_str();


	

	CRYPTO_malloc_locked(arg0,arg1,arg2);
}

// int EVP_read_pw_string_min(char *, int, int, const char *, int)
void F8af6f76675040e8c7615369e0de9e87c86429df5(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 5) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg1;

	if (!FromBigInt(args, 1, arg1)) {
                return;
        }


	
	   
        int arg2;

	if (!FromBigInt(args, 2, arg2)) {
                return;
        }


	
	   
        int arg4;

	if (!FromBigInt(args, 4, arg4)) {
                return;
        }


	
	   
        char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (char *)arg0container.c_str();


	
	   
        const char * arg3;

        std::string arg3container;
        if (!Fromstring(args, 3, arg3container)) {
                return;
        }

	arg3 = (const char *)arg3container.c_str();


	

	EVP_read_pw_string_min(arg0,arg1,arg2,arg3,arg4);
}

// int rotate_index(const char *, const char *, const char *)
void Ff75ea5a2a99da9e296edd68fb96d7c2ed5406f76(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 3) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	
	   
        const char * arg1;

        std::string arg1container;
        if (!Fromstring(args, 1, arg1container)) {
                return;
        }

	arg1 = (const char *)arg1container.c_str();


	
	   
        const char * arg2;

        std::string arg2container;
        if (!Fromstring(args, 2, arg2container)) {
                return;
        }

	arg2 = (const char *)arg2container.c_str();


	

	rotate_index(arg0,arg1,arg2);
}

// double app_tminterval(int, int)
void F5b335a8cd08cdcf4ab52edac09273384629f1d81(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 2) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	
	   
        int arg1;

	if (!FromBigInt(args, 1, arg1)) {
                return;
        }


	

	app_tminterval(arg0,arg1);
}

// void PEM_proc_type(char *, int)
void F9ebf465984b4d3d462df0a85efc1d1a57dd366e1(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 2) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg1;

	if (!FromBigInt(args, 1, arg1)) {
                return;
        }


	
	   
        char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (char *)arg0container.c_str();


	

	PEM_proc_type(arg0,arg1);
}

// void ENGINE_set_table_flags(unsigned int)
void Ffc3eae03b7c6147bf704a41143b3201aac8e678b(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        unsigned int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	ENGINE_set_table_flags(arg0);
}

// struct asn1_string_st *ASN1_STRING_type_new(int)
void Fee3438b457610e881d1a76fabc55c781cb12f60a(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	ASN1_STRING_type_new(arg0);
}

// struct engine_st *ENGINE_get_cipher_engine(int)
void Ff99cd567e7c2229386d56a60def3b18335e66f45(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	ENGINE_get_cipher_engine(arg0);
}

// int X509_TRUST_get_by_id(int)
void F1a0ad24f960f06ef6bb0504fedc40939c73b5924(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	X509_TRUST_get_by_id(arg0);
}

// int RSA_X931_hash_id(int)
void Faa02fdc38bd323a2509f2aee2cd527139090d38b(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	RSA_X931_hash_id(arg0);
}

// struct SRP_VBASE_st *SRP_VBASE_new(char *)
void F4712dea9ac1fbf1aca226ba1ba0856973b00880b(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (char *)arg0container.c_str();


	

	SRP_VBASE_new(arg0);
}

// int OBJ_txt2nid(const char *)
void F95518f2242375dacb0a81acf93538e2357043b1e(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	

	OBJ_txt2nid(arg0);
}

// int BIO_sock_should_retry(int)
void Fbba77e6a898ffb5603d4cd5222a8baff6e48154c(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	BIO_sock_should_retry(arg0);
}

// long app_RAND_load_files(char *)
void Fb88a76850c4eca4c72763b708392a3e8912feb41(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (char *)arg0container.c_str();


	

	app_RAND_load_files(arg0);
}

// struct x509_purpose_st *X509_PURPOSE_get0(int)
void F4e7b9aef1fb091f2fdba85081fe6d2f9641fb234(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	X509_PURPOSE_get0(arg0);
}

// void CRYPTO_lock(int, int, const char *, int)
void F16f7edcd1a50c072c57dfb946cfd71b01b6135b5(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 4) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	
	   
        int arg1;

	if (!FromBigInt(args, 1, arg1)) {
                return;
        }


	
	   
        int arg3;

	if (!FromBigInt(args, 3, arg3)) {
                return;
        }


	
	   
        const char * arg2;

        std::string arg2container;
        if (!Fromstring(args, 2, arg2container)) {
                return;
        }

	arg2 = (const char *)arg2container.c_str();


	

	CRYPTO_lock(arg0,arg1,arg2,arg3);
}

// struct engine_st *ENGINE_get_pkey_asn1_meth_engine(int)
void Fa76e0fccaf363a0e1497edba0fb8dc01118d5679(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	ENGINE_get_pkey_asn1_meth_engine(arg0);
}

// int X509_REQ_extension_nid(int)
void Fbaa47876d40e51082bc810e6fd6d1762a5bb1e67(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	X509_REQ_extension_nid(arg0);
}

// int ASN1_STRING_TABLE_add(int, long, long, unsigned long, unsigned long)
void F038b95ea39c67b844ab65dc0a780f70cae7e6c2a(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 5) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	
	   
        long arg1;

	if (!FromBigInt(args, 1, arg1)) {
                return;
        }


	
	   
        long arg2;

	if (!FromBigInt(args, 2, arg2)) {
                return;
        }


	
	   
        unsigned long arg3;

	if (!FromBigInt(args, 3, arg3)) {
                return;
        }


	
	   
        unsigned long arg4;

	if (!FromBigInt(args, 4, arg4)) {
                return;
        }


	

	ASN1_STRING_TABLE_add(arg0,arg1,arg2,arg3,arg4);
}

// const char *ERR_lib_error_string(unsigned long)
void F7b8024edd2cb6c3f1cc8078f7ef45be917f629cb(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        unsigned long arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	ERR_lib_error_string(arg0);
}

// int OBJ_add_sigid(int, int, int)
void F4d4414daaba1955bbf79d269e1b7ba839cdc9ca4(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 3) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	
	   
        int arg1;

	if (!FromBigInt(args, 1, arg1)) {
                return;
        }


	
	   
        int arg2;

	if (!FromBigInt(args, 2, arg2)) {
                return;
        }


	

	OBJ_add_sigid(arg0,arg1,arg2);
}

// void CONF_modules_unload(int)
void Ff6d2c477c7f13e1e899f957615eb749dbd57b8d6(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	CONF_modules_unload(arg0);
}

// int ASN1_object_size(int, int, int)
void F8d6a9fe332e35d8a57ac25a353245f25c512003e(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 3) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	
	   
        int arg1;

	if (!FromBigInt(args, 1, arg1)) {
                return;
        }


	
	   
        int arg2;

	if (!FromBigInt(args, 2, arg2)) {
                return;
        }


	

	ASN1_object_size(arg0,arg1,arg2);
}

// struct X509_name_st *parse_name(char *, long, int)
void F4329736e1589184872835a4f98db8eb5af70fbf7(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 3) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg2;

	if (!FromBigInt(args, 2, arg2)) {
                return;
        }


	
	   
        long arg1;

	if (!FromBigInt(args, 1, arg1)) {
                return;
        }


	
	   
        char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (char *)arg0container.c_str();


	

	parse_name(arg0,arg1,arg2);
}

// void PEM_dek_info(char *, const char *, int, char *)
void F37a306f689a08e7c2e1e17eab539f5be6e77b66e(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 4) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg2;

	if (!FromBigInt(args, 2, arg2)) {
                return;
        }


	
	   
        char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (char *)arg0container.c_str();


	
	   
        const char * arg1;

        std::string arg1container;
        if (!Fromstring(args, 1, arg1container)) {
                return;
        }

	arg1 = (const char *)arg1container.c_str();


	
	   
        char * arg3;

        std::string arg3container;
        if (!Fromstring(args, 3, arg3container)) {
                return;
        }

	arg3 = (char *)arg3container.c_str();


	

	PEM_dek_info(arg0,arg1,arg2,arg3);
}

// void ASN1_STRING_set_default_mask(unsigned long)
void Fc036a5579c62496353b3324cb8602a237939e243(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        unsigned long arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	ASN1_STRING_set_default_mask(arg0);
}

// int name_cmp(const char *, const char *)
void F9b78f1f5586a6d31329c27fc8c37cbba8cea1970(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 2) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	
	   
        const char * arg1;

        std::string arg1container;
        if (!Fromstring(args, 1, arg1container)) {
                return;
        }

	arg1 = (const char *)arg1container.c_str();


	

	name_cmp(arg0,arg1);
}

// const char *OBJ_NAME_get(const char *, int)
void F0ee2a72b66ef5ee7d90c8adbaa3d80ecaff3c6db(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 2) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg1;

	if (!FromBigInt(args, 1, arg1)) {
                return;
        }


	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	

	OBJ_NAME_get(arg0,arg1);
}

// void BN_set_params(int, int, int, int)
void F041b27d285caa212cbb08c4035c69451a07ef25f(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 4) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	
	   
        int arg1;

	if (!FromBigInt(args, 1, arg1)) {
                return;
        }


	
	   
        int arg2;

	if (!FromBigInt(args, 2, arg2)) {
                return;
        }


	
	   
        int arg3;

	if (!FromBigInt(args, 3, arg3)) {
                return;
        }


	

	BN_set_params(arg0,arg1,arg2,arg3);
}

// unsigned long ASN1_tag2bit(int)
void F9317c7310716ce636e0ea3c84e4161f09b046621(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	ASN1_tag2bit(arg0);
}

// const struct ssl_cipher_st *ssl23_get_cipher(unsigned int)
void F7f9cfc39e7a1e02a02d3d84aa3e661496aa80224(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        unsigned int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	ssl23_get_cipher(arg0);
}

// int tls1_ec_nid2curve_id(int)
void F8ac4c09b073ffc7e7aee718460a3aa90ad6c1ad4(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	tls1_ec_nid2curve_id(arg0);
}

// const char *SSL_alert_type_string(int)
void Fd2b196423662824548125de52937919264c5a553(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	SSL_alert_type_string(arg0);
}

// char *BUF_strndup(const char *, unsigned long)
void F08e08b0ce3ff218c6ea2ff98d7de97554a0582b3(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 2) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
#if V8_MAJOR_VERSION < 8
	v8::ArrayBuffer::Contents arg0;
#else
	std::shared_ptr<v8::BackingStore> arg0;
#endif
	{
		Local<Value> arg = args[0];
		if (!arg->IsArrayBufferView()) {
			_excTypeNotA(isolate, 0, "array buffer view");
			return;
		}

		Local<v8::ArrayBufferView> view =
		    v8::Local<v8::ArrayBufferView>::Cast(arg);

#if V8_MAJOR_VERSION < 8
		arg0 = view->Buffer()->GetContents();
#else
		arg0 = view->Buffer()->GetBackingStore();
#endif
	}

	

	BUF_strndup(
#if V8_MAJOR_VERSION < 8
	(const char *)arg0.Data()
#else
	(const char *)arg0->Data()
#endif
,
#if V8_MAJOR_VERSION < 8
	(unsigned long)arg0.ByteLength()
#else
	(unsigned long)arg0->ByteLength()
#endif
);
}

// struct stack_st_CONF_VALUE *X509V3_parse_list(const char *)
void F4d10e764b76687a6c390fc019a1bec479ca241c1(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	

	X509V3_parse_list(arg0);
}

// struct asn1_object_st *OBJ_txt2obj(const char *, int)
void F9261d350d6293b95eff793a0e4b54077167908df(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 2) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg1;

	if (!FromBigInt(args, 1, arg1)) {
                return;
        }


	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	

	OBJ_txt2obj(arg0,arg1);
}

// int tls1_ec_curve_id2nid(int)
void F3ffbd77e38b703ce0b310326a92bcfc6fad31ea2(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	tls1_ec_curve_id2nid(arg0);
}

// const char *SSL_alert_desc_string_long(int)
void F067a0c4bb134af4744afce63433406e7c80394c2(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	SSL_alert_desc_string_long(arg0);
}

// int OBJ_create(const char *, const char *, const char *)
void F178c7c8f9a31ec105b74563bf462289171172284(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 3) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	
	   
        const char * arg1;

        std::string arg1container;
        if (!Fromstring(args, 1, arg1container)) {
                return;
        }

	arg1 = (const char *)arg1container.c_str();


	
	   
        const char * arg2;

        std::string arg2container;
        if (!Fromstring(args, 2, arg2container)) {
                return;
        }

	arg2 = (const char *)arg2container.c_str();


	

	OBJ_create(arg0,arg1,arg2);
}

// void program_name(char *, char *, int)
void F0acd9799353eb07afc0dd218536343cd3434980c(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 3) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg2;

	if (!FromBigInt(args, 2, arg2)) {
                return;
        }


	
	   
        char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (char *)arg0container.c_str();


	
	   
        char * arg1;

        std::string arg1container;
        if (!Fromstring(args, 1, arg1container)) {
                return;
        }

	arg1 = (char *)arg1container.c_str();


	

	program_name(arg0,arg1,arg2);
}

// int FuzzerEntrypoint(const unsigned char *, unsigned long)
void F7edcf1f0d8c089d919e1bcd8c0f8603303446385(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 2) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
#if V8_MAJOR_VERSION < 8
	v8::ArrayBuffer::Contents arg0;
#else
	std::shared_ptr<v8::BackingStore> arg0;
#endif
	{
		Local<Value> arg = args[0];
		if (!arg->IsArrayBufferView()) {
			_excTypeNotA(isolate, 0, "array buffer view");
			return;
		}

		Local<v8::ArrayBufferView> view =
		    v8::Local<v8::ArrayBufferView>::Cast(arg);

#if V8_MAJOR_VERSION < 8
		arg0 = view->Buffer()->GetContents();
#else
		arg0 = view->Buffer()->GetBackingStore();
#endif
	}

	

	FuzzerEntrypoint(
#if V8_MAJOR_VERSION < 8
	(const unsigned char *)arg0.Data()
#else
	(const unsigned char *)arg0->Data()
#endif
,
#if V8_MAJOR_VERSION < 8
	(unsigned long)arg0.ByteLength()
#else
	(unsigned long)arg0->ByteLength()
#endif
);
}

// int ASN1_STRING_set_default_mask_asc(const char *)
void Ffd174d30c2aedff651e9d313705f98d503d5c5d0(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	

	ASN1_STRING_set_default_mask_asc(arg0);
}

// void ERR_put_error(int, int, int, const char *, int)
void Fa6dd7e91f8d016443706dd74439d19194164225f(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 5) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	
	   
        int arg1;

	if (!FromBigInt(args, 1, arg1)) {
                return;
        }


	
	   
        int arg2;

	if (!FromBigInt(args, 2, arg2)) {
                return;
        }


	
	   
        int arg4;

	if (!FromBigInt(args, 4, arg4)) {
                return;
        }


	
	   
        const char * arg3;

        std::string arg3container;
        if (!Fromstring(args, 3, arg3container)) {
                return;
        }

	arg3 = (const char *)arg3container.c_str();


	

	ERR_put_error(arg0,arg1,arg2,arg3,arg4);
}

// int OBJ_ln2nid(const char *)
void F0bd060e375f198fcd8462888f79e6edf7387a4c5(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	

	OBJ_ln2nid(arg0);
}

// int ssl_verify_alarm_type(long)
void Fccbaf4004fbbf38aeb34e3681f34a6688e047716(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        long arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	ssl_verify_alarm_type(arg0);
}

// int CRYPTO_mem_ctrl(int)
void F3535a390f029534b7299ab3d55ef37fb80ed7c5c(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	CRYPTO_mem_ctrl(arg0);
}

// const struct evp_cipher_st *EVP_get_cipherbyname(const char *)
void F2419add76f8cd55715547acc4402a815fa0eeb4a(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	

	EVP_get_cipherbyname(arg0);
}

// const char *OBJ_nid2ln(int)
void F6547564823d8009aca81830335e18b7737d66dca(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	

	OBJ_nid2ln(arg0);
}

// struct bio_st *BIO_new_socket(int, int)
void F2562d216df5ea9122a08251a0b1087b472bfdec8(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 2) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        int arg0;

	if (!FromBigInt(args, 0, arg0)) {
                return;
        }


	
	   
        int arg1;

	if (!FromBigInt(args, 1, arg1)) {
                return;
        }


	

	BIO_new_socket(arg0,arg1);
}

// struct engine_st *ENGINE_by_id(const char *)
void F9bdd83dd17fa8f01e7fe2753a8f0b0cd945805ef(const FunctionCallbackInfo<Value> &args)
{
	v8::Isolate *isolate = args.GetIsolate();
	v8::HandleScope scope(isolate);

	if (args.Length() != 1) {
		_excMsg(isolate, "incorrect number of arguments");
		return;
	}

	
	   
        const char * arg0;

        std::string arg0container;
        if (!Fromstring(args, 0, arg0container)) {
                return;
        }

	arg0 = (const char *)arg0container.c_str();


	

	ENGINE_by_id(arg0);
}


#ifdef USING_BEX
extern "C" void Initialize(Local<Object> exports)
{
	// From coverage.cc
	bex::es::setMethod(exports, "Get8BitCounters", Get8BitCounters);
	bex::es::setMethod(exports, "Reset8BitCounters", Reset8BitCounters);
	bex::es::setMethod(exports, "GetComparisonBitmap", GetComparisonBitmap);

	
	bex::es::setMethod(exports, "X509V3_EXT_add_alias", Ff5c353af12e050f9b075655f13344c90cfbfb835);
	
	bex::es::setMethod(exports, "OBJ_NAME_remove", Fbdde52fc0aa3122703e226e66355688b4eba7376);
	
	bex::es::setMethod(exports, "X509_PURPOSE_get_by_sname", Ff6e9941f5fdf360fc1fc2e9410a72bb53cb23bc3);
	
	bex::es::setMethod(exports, "OBJ_NAME_add", F6540b5cec98edbaa65a07f5435a2f19792cdf4ef);
	
	bex::es::setMethod(exports, "make_revocation_str", Fab452aae83fdb7543bcdbcce8234adc0869cd97e);
	
	bex::es::setMethod(exports, "SSL_load_client_CA_file", F5c9f55f0750024d45ac6dd88f01add42be330ff0);
	
	bex::es::setMethod(exports, "CONF_modules_load_file", Fa561a51799a68a95f687e8189e1f15f5319834ea);
	
	bex::es::setMethod(exports, "ASN1_tag2str", F22354db8a27cb2263d0a119c7d9c88cf86442fe9);
	
	bex::es::setMethod(exports, "app_isdir", F91aa3575215ce93743ed6c84f693423850887d8b);
	
	bex::es::setMethod(exports, "check_defer", F967eb4e00b6b220c4986e65dd50c8d6746dfc586);
	
	bex::es::setMethod(exports, "str2fmt", F91dd22988f5e3fe5d6b7f474d898b6679d55382a);
	
	bex::es::setMethod(exports, "BN_num_bits_word", Fe9c2e889e8cb007b9397686f9ddf68fbb432ded7);
	
	bex::es::setMethod(exports, "EVP_PKEY_asn1_new", Fd99514fde33712a8cafc36f61288dcb9d2979600);
	
	bex::es::setMethod(exports, "BN_get_params", F03570939aff17c4c5b100ca90efd3546d24ec2e5);
	
	bex::es::setMethod(exports, "CRYPTO_malloc", F3f891508b4018fdbdc77c5a8a94b52efa6c44866);
	
	bex::es::setMethod(exports, "EVP_PKEY_meth_new", F9007108531962d8f270c746313eaa03b341109ea);
	
	bex::es::setMethod(exports, "EVP_PKEY_meth_find", Fe97ff9adb5bfb7bb500c2224d30832aab6fffabd);
	
	bex::es::setMethod(exports, "CRYPTO_get_new_lockid", F98402ab8e1e9be0331fe309fc933b90a712de7be);
	
	bex::es::setMethod(exports, "ssl2_get_cipher", Fe8a6e624890d1d016813ea8da358c65e00d095b4);
	
	bex::es::setMethod(exports, "X509_TRUST_get0", F04ac48616804a41d5cf31f9d5b1f4c69d66b7cab);
	
	bex::es::setMethod(exports, "EVP_PKEY_type", Feab34d6bd1e1908270a948da4619c990a70b637f);
	
	bex::es::setMethod(exports, "BUF_strlcat", F35b2579c7dc1055c655c2cd192ba9d74637eead7);
	
	bex::es::setMethod(exports, "dtls1_get_cipher", F178db9e12c3140d00dddd2e60fc5d17b9a15e50d);
	
	bex::es::setMethod(exports, "CRYPTO_destroy_dynlockid", F96ce81ead890005724e32baeb740fbf1e72491e7);
	
	bex::es::setMethod(exports, "ssl3_alert_code", Fcd5bbec33510a2bb830434212b280b3a8eba747f);
	
	bex::es::setMethod(exports, "ssl3_get_cipher", Fd377300718c7787d1951b8305c6b43dab0e55d1a);
	
	bex::es::setMethod(exports, "ERR_set_error_data", Fbca24acef13389fa41f1e6f994b2e5a5593313c1);
	
	bex::es::setMethod(exports, "lh_strhash", F00870b23e2f1aa2d60f1077afe068779905a6b7c);
	
	bex::es::setMethod(exports, "OBJ_NAME_cleanup", Fe62a0fb5ea4a4e3d441f82264e8f419b64f83df1);
	
	bex::es::setMethod(exports, "ERR_error_string", Fb8320143fb66752b5acf0749720e917aacf0fdae);
	
	bex::es::setMethod(exports, "parse_yesno", F0343cc72d1404268343721d3f392bf214d3b2d97);
	
	bex::es::setMethod(exports, "BIO_new_file", F04b160c04b6b047e2c95ae53e03f14237bf56cc1);
	
	bex::es::setMethod(exports, "EVP_PKEY_asn1_get0", Fc094fb7d243ebfdff2012fb323e0ac1ceb055840);
	
	bex::es::setMethod(exports, "ASN1_STRING_TABLE_get", F45a6c15bf8aebed2bd07660d26d6410f7995cab7);
	
	bex::es::setMethod(exports, "pem_check_suffix", Fcae7001bca697e1ebc6593e5f07670a4ff0557e9);
	
	bex::es::setMethod(exports, "ERR_remove_state", F43e54da7587da68b838b74d471d51027bfc4d9d2);
	
	bex::es::setMethod(exports, "UI_create_method", F2905eaf84829553f109d69cd0e8e3cbb3db4a9ad);
	
	bex::es::setMethod(exports, "OBJ_nid2obj", F9c15cea8f4734fadc396ec0b90726dea1f149644);
	
	bex::es::setMethod(exports, "SSL_alert_type_string_long", Fa64c4183ebf34775e342b7db8f185e53224092c9);
	
	bex::es::setMethod(exports, "CRYPTO_set_mem_debug_options", F076dd4e443ac7604a639be4dcafce7ed8642edfc);
	
	bex::es::setMethod(exports, "OBJ_sn2nid", F04ca27d2727d2f59cac0bf37b440d9072fc6b7cc);
	
	bex::es::setMethod(exports, "RAND_egd_bytes", Ff5bfae44e404ecab5babcaa9a9868dbf2843a5e3);
	
	bex::es::setMethod(exports, "BIO_sock_non_fatal_error", F28e7ab0aff8acd1488479d8e3d3684a65f3a3e48);
	
	bex::es::setMethod(exports, "OpenSSLDie", F300d5d9f4acaa96a3e19b5c5b7cd0751217d8999);
	
	bex::es::setMethod(exports, "EC_KEY_new_by_curve_name", F6b51b926459b8d06ce56f207d0eac23f1cb48e3f);
	
	bex::es::setMethod(exports, "ssl_bad_method", F843a70847ed7f94a5050e239388247fe2f51a70e);
	
	bex::es::setMethod(exports, "BUF_strdup", Fb1bd9e6bb5c712af29fb86024e274d36728dde60);
	
	bex::es::setMethod(exports, "EC_GROUP_new_by_curve_name", Fa870d3ec6367b211d530e84081789035e48d9f53);
	
	bex::es::setMethod(exports, "ERR_reason_error_string", Faeafccd98c1a29b1a43d7c8263d95a4c09b04bf6);
	
	bex::es::setMethod(exports, "tls12_get_hash", Ffcb6e9345977648c45c5a9b507cd74bc77095caa);
	
	bex::es::setMethod(exports, "dtls1_get_queue_priority", F9a51bb8b7186ea32ad6c2a1a2106107e4c355c0c);
	
	bex::es::setMethod(exports, "CRYPTO_get_dynlock_value", Fdd13e1e75414735910056181e4243b15290c2499);
	
	bex::es::setMethod(exports, "tls1_alert_code", F465d2b978111476900f8a0851870c20ed035a795);
	
	bex::es::setMethod(exports, "BUF_strlcpy", F505571b978dcbfbec6f2cdaeccfec3ef04e1ed49);
	
	bex::es::setMethod(exports, "X509_VERIFY_PARAM_lookup", Fb818030be70dd7462e11aaf7abc7a28fe1962153);
	
	bex::es::setMethod(exports, "X509_PURPOSE_get_by_id", Fd063720e4cb29e6e6794c4d5d367c5bbaa9033d9);
	
	bex::es::setMethod(exports, "ENGINE_get_digest_engine", Fbdad082abdb69c313ff040a65e4cdb08e3107677);
	
	bex::es::setMethod(exports, "X509V3_EXT_get_nid", F4c5bbe1a85b8b8a9ba3fee167c5678edcc316ffd);
	
	bex::es::setMethod(exports, "CRYPTO_push_info_", F6c398d138afb6fff67fa2c9182946d3383fb4866);
	
	bex::es::setMethod(exports, "DSO_global_lookup", Fd2535c701d4e09f548989a3ef86a6c6f3c03604b);
	
	bex::es::setMethod(exports, "SRP_get_default_gN", F608b32cfaab5c93dc4c7b4954dcc6e85029bd4cf);
	
	bex::es::setMethod(exports, "ENGINE_get_pkey_meth_engine", Fa7fb86003a76e2553bbe57b40b699db72353a4e3);
	
	bex::es::setMethod(exports, "CRYPTO_get_lock_name", F22e38a1127e5dd20729c4c7385dd313a74875195);
	
	bex::es::setMethod(exports, "SSL_alert_desc_string", F378f1050c368e5bb809952a4babce43fa6ed3fa1);
	
	bex::es::setMethod(exports, "a2i_IPADDRESS", Ff6c3c1e8c7585e606feaa1c1ebda69e590491bbd);
	
	bex::es::setMethod(exports, "EVP_set_pw_prompt", F553e95e7d0d11368328c693892132ed32c6bde8e);
	
	bex::es::setMethod(exports, "rotate_serial", F3a6de72dc6a9231821fdd1857ef99fe8fc2479e5);
	
	bex::es::setMethod(exports, "EVP_read_pw_string", Fd6d0e1643d32c580ed02aabfed4eea7a31259821);
	
	bex::es::setMethod(exports, "EVP_get_digestbyname", Ff13bbe52960485801a22bca127731aff6571ea00);
	
	bex::es::setMethod(exports, "OBJ_new_nid", F5b0f88f7b3515766bc77c5e2b3538917d3ae50ba);
	
	bex::es::setMethod(exports, "RAND_egd", F7741397c54505522901b321d04a0f0181d96bd87);
	
	bex::es::setMethod(exports, "ERR_func_error_string", Fb7fd0942506396403329e499416c8145d21fff8d);
	
	bex::es::setMethod(exports, "OBJ_nid2sn", Fdbaa8d10bfcc89f27e7c15dc93e9b2cb148c8a9e);
	
	bex::es::setMethod(exports, "ERR_error_string_n", Feb3e496e35232aeb5b7ead4d6e2fd112e0c8bcb0);
	
	bex::es::setMethod(exports, "a2i_IPADDRESS_NC", F52b8b0b795b676bc9472876c6e75152d885aacdc);
	
	bex::es::setMethod(exports, "CRYPTO_dbg_set_options", F82335ac28b86f5ea26de5c171cdd936789beda08);
	
	bex::es::setMethod(exports, "app_init", F6cef3c719d5773777c1f415016dcb77c817d8e08);
	
	bex::es::setMethod(exports, "bn_div_words", F18ad0ab09eabd710082995c5427ba3efc36bc21a);
	
	bex::es::setMethod(exports, "CRYPTO_strdup", Fd6b01b638bdc9193db96414949f5a27d34b814c6);
	
	bex::es::setMethod(exports, "EVP_PKEY_asn1_add_alias", F1375428682ae931890b9506be00b036dd3cd6a9b);
	
	bex::es::setMethod(exports, "CRYPTO_malloc_locked", F35210f71d91dd9633ef15f6c0423b32acf77b808);
	
	bex::es::setMethod(exports, "EVP_read_pw_string_min", F8af6f76675040e8c7615369e0de9e87c86429df5);
	
	bex::es::setMethod(exports, "rotate_index", Ff75ea5a2a99da9e296edd68fb96d7c2ed5406f76);
	
	bex::es::setMethod(exports, "app_tminterval", F5b335a8cd08cdcf4ab52edac09273384629f1d81);
	
	bex::es::setMethod(exports, "PEM_proc_type", F9ebf465984b4d3d462df0a85efc1d1a57dd366e1);
	
	bex::es::setMethod(exports, "ENGINE_set_table_flags", Ffc3eae03b7c6147bf704a41143b3201aac8e678b);
	
	bex::es::setMethod(exports, "ASN1_STRING_type_new", Fee3438b457610e881d1a76fabc55c781cb12f60a);
	
	bex::es::setMethod(exports, "ENGINE_get_cipher_engine", Ff99cd567e7c2229386d56a60def3b18335e66f45);
	
	bex::es::setMethod(exports, "X509_TRUST_get_by_id", F1a0ad24f960f06ef6bb0504fedc40939c73b5924);
	
	bex::es::setMethod(exports, "RSA_X931_hash_id", Faa02fdc38bd323a2509f2aee2cd527139090d38b);
	
	bex::es::setMethod(exports, "SRP_VBASE_new", F4712dea9ac1fbf1aca226ba1ba0856973b00880b);
	
	bex::es::setMethod(exports, "OBJ_txt2nid", F95518f2242375dacb0a81acf93538e2357043b1e);
	
	bex::es::setMethod(exports, "BIO_sock_should_retry", Fbba77e6a898ffb5603d4cd5222a8baff6e48154c);
	
	bex::es::setMethod(exports, "app_RAND_load_files", Fb88a76850c4eca4c72763b708392a3e8912feb41);
	
	bex::es::setMethod(exports, "X509_PURPOSE_get0", F4e7b9aef1fb091f2fdba85081fe6d2f9641fb234);
	
	bex::es::setMethod(exports, "CRYPTO_lock", F16f7edcd1a50c072c57dfb946cfd71b01b6135b5);
	
	bex::es::setMethod(exports, "ENGINE_get_pkey_asn1_meth_engine", Fa76e0fccaf363a0e1497edba0fb8dc01118d5679);
	
	bex::es::setMethod(exports, "X509_REQ_extension_nid", Fbaa47876d40e51082bc810e6fd6d1762a5bb1e67);
	
	bex::es::setMethod(exports, "ASN1_STRING_TABLE_add", F038b95ea39c67b844ab65dc0a780f70cae7e6c2a);
	
	bex::es::setMethod(exports, "ERR_lib_error_string", F7b8024edd2cb6c3f1cc8078f7ef45be917f629cb);
	
	bex::es::setMethod(exports, "OBJ_add_sigid", F4d4414daaba1955bbf79d269e1b7ba839cdc9ca4);
	
	bex::es::setMethod(exports, "CONF_modules_unload", Ff6d2c477c7f13e1e899f957615eb749dbd57b8d6);
	
	bex::es::setMethod(exports, "ASN1_object_size", F8d6a9fe332e35d8a57ac25a353245f25c512003e);
	
	bex::es::setMethod(exports, "parse_name", F4329736e1589184872835a4f98db8eb5af70fbf7);
	
	bex::es::setMethod(exports, "PEM_dek_info", F37a306f689a08e7c2e1e17eab539f5be6e77b66e);
	
	bex::es::setMethod(exports, "ASN1_STRING_set_default_mask", Fc036a5579c62496353b3324cb8602a237939e243);
	
	bex::es::setMethod(exports, "name_cmp", F9b78f1f5586a6d31329c27fc8c37cbba8cea1970);
	
	bex::es::setMethod(exports, "OBJ_NAME_get", F0ee2a72b66ef5ee7d90c8adbaa3d80ecaff3c6db);
	
	bex::es::setMethod(exports, "BN_set_params", F041b27d285caa212cbb08c4035c69451a07ef25f);
	
	bex::es::setMethod(exports, "ASN1_tag2bit", F9317c7310716ce636e0ea3c84e4161f09b046621);
	
	bex::es::setMethod(exports, "ssl23_get_cipher", F7f9cfc39e7a1e02a02d3d84aa3e661496aa80224);
	
	bex::es::setMethod(exports, "tls1_ec_nid2curve_id", F8ac4c09b073ffc7e7aee718460a3aa90ad6c1ad4);
	
	bex::es::setMethod(exports, "SSL_alert_type_string", Fd2b196423662824548125de52937919264c5a553);
	
	bex::es::setMethod(exports, "BUF_strndup", F08e08b0ce3ff218c6ea2ff98d7de97554a0582b3);
	
	bex::es::setMethod(exports, "X509V3_parse_list", F4d10e764b76687a6c390fc019a1bec479ca241c1);
	
	bex::es::setMethod(exports, "OBJ_txt2obj", F9261d350d6293b95eff793a0e4b54077167908df);
	
	bex::es::setMethod(exports, "tls1_ec_curve_id2nid", F3ffbd77e38b703ce0b310326a92bcfc6fad31ea2);
	
	bex::es::setMethod(exports, "SSL_alert_desc_string_long", F067a0c4bb134af4744afce63433406e7c80394c2);
	
	bex::es::setMethod(exports, "OBJ_create", F178c7c8f9a31ec105b74563bf462289171172284);
	
	bex::es::setMethod(exports, "program_name", F0acd9799353eb07afc0dd218536343cd3434980c);
	
	bex::es::setMethod(exports, "FuzzerEntrypoint", F7edcf1f0d8c089d919e1bcd8c0f8603303446385);
	
	bex::es::setMethod(exports, "ASN1_STRING_set_default_mask_asc", Ffd174d30c2aedff651e9d313705f98d503d5c5d0);
	
	bex::es::setMethod(exports, "ERR_put_error", Fa6dd7e91f8d016443706dd74439d19194164225f);
	
	bex::es::setMethod(exports, "OBJ_ln2nid", F0bd060e375f198fcd8462888f79e6edf7387a4c5);
	
	bex::es::setMethod(exports, "ssl_verify_alarm_type", Fccbaf4004fbbf38aeb34e3681f34a6688e047716);
	
	bex::es::setMethod(exports, "CRYPTO_mem_ctrl", F3535a390f029534b7299ab3d55ef37fb80ed7c5c);
	
	bex::es::setMethod(exports, "EVP_get_cipherbyname", F2419add76f8cd55715547acc4402a815fa0eeb4a);
	
	bex::es::setMethod(exports, "OBJ_nid2ln", F6547564823d8009aca81830335e18b7737d66dca);
	
	bex::es::setMethod(exports, "BIO_new_socket", F2562d216df5ea9122a08251a0b1087b472bfdec8);
	
	bex::es::setMethod(exports, "ENGINE_by_id", F9bdd83dd17fa8f01e7fe2753a8f0b0cd945805ef);
	
}
#else
void Initialize(Local<Object> exports, Local<Value> hey, void *you)
{
	// From coverage.cc
	NODE_SET_METHOD(exports, "Get8BitCounters", Get8BitCounters);
	NODE_SET_METHOD(exports, "Reset8BitCounters", Reset8BitCounters);
	NODE_SET_METHOD(exports, "GetComparisonBitmap", GetComparisonBitmap);

        
        NODE_SET_METHOD(exports, "X509V3_EXT_add_alias", Ff5c353af12e050f9b075655f13344c90cfbfb835);	
        
        NODE_SET_METHOD(exports, "OBJ_NAME_remove", Fbdde52fc0aa3122703e226e66355688b4eba7376);	
        
        NODE_SET_METHOD(exports, "X509_PURPOSE_get_by_sname", Ff6e9941f5fdf360fc1fc2e9410a72bb53cb23bc3);	
        
        NODE_SET_METHOD(exports, "OBJ_NAME_add", F6540b5cec98edbaa65a07f5435a2f19792cdf4ef);	
        
        NODE_SET_METHOD(exports, "make_revocation_str", Fab452aae83fdb7543bcdbcce8234adc0869cd97e);	
        
        NODE_SET_METHOD(exports, "SSL_load_client_CA_file", F5c9f55f0750024d45ac6dd88f01add42be330ff0);	
        
        NODE_SET_METHOD(exports, "CONF_modules_load_file", Fa561a51799a68a95f687e8189e1f15f5319834ea);	
        
        NODE_SET_METHOD(exports, "ASN1_tag2str", F22354db8a27cb2263d0a119c7d9c88cf86442fe9);	
        
        NODE_SET_METHOD(exports, "app_isdir", F91aa3575215ce93743ed6c84f693423850887d8b);	
        
        NODE_SET_METHOD(exports, "check_defer", F967eb4e00b6b220c4986e65dd50c8d6746dfc586);	
        
        NODE_SET_METHOD(exports, "str2fmt", F91dd22988f5e3fe5d6b7f474d898b6679d55382a);	
        
        NODE_SET_METHOD(exports, "BN_num_bits_word", Fe9c2e889e8cb007b9397686f9ddf68fbb432ded7);	
        
        NODE_SET_METHOD(exports, "EVP_PKEY_asn1_new", Fd99514fde33712a8cafc36f61288dcb9d2979600);	
        
        NODE_SET_METHOD(exports, "BN_get_params", F03570939aff17c4c5b100ca90efd3546d24ec2e5);	
        
        NODE_SET_METHOD(exports, "CRYPTO_malloc", F3f891508b4018fdbdc77c5a8a94b52efa6c44866);	
        
        NODE_SET_METHOD(exports, "EVP_PKEY_meth_new", F9007108531962d8f270c746313eaa03b341109ea);	
        
        NODE_SET_METHOD(exports, "EVP_PKEY_meth_find", Fe97ff9adb5bfb7bb500c2224d30832aab6fffabd);	
        
        NODE_SET_METHOD(exports, "CRYPTO_get_new_lockid", F98402ab8e1e9be0331fe309fc933b90a712de7be);	
        
        NODE_SET_METHOD(exports, "ssl2_get_cipher", Fe8a6e624890d1d016813ea8da358c65e00d095b4);	
        
        NODE_SET_METHOD(exports, "X509_TRUST_get0", F04ac48616804a41d5cf31f9d5b1f4c69d66b7cab);	
        
        NODE_SET_METHOD(exports, "EVP_PKEY_type", Feab34d6bd1e1908270a948da4619c990a70b637f);	
        
        NODE_SET_METHOD(exports, "BUF_strlcat", F35b2579c7dc1055c655c2cd192ba9d74637eead7);	
        
        NODE_SET_METHOD(exports, "dtls1_get_cipher", F178db9e12c3140d00dddd2e60fc5d17b9a15e50d);	
        
        NODE_SET_METHOD(exports, "CRYPTO_destroy_dynlockid", F96ce81ead890005724e32baeb740fbf1e72491e7);	
        
        NODE_SET_METHOD(exports, "ssl3_alert_code", Fcd5bbec33510a2bb830434212b280b3a8eba747f);	
        
        NODE_SET_METHOD(exports, "ssl3_get_cipher", Fd377300718c7787d1951b8305c6b43dab0e55d1a);	
        
        NODE_SET_METHOD(exports, "ERR_set_error_data", Fbca24acef13389fa41f1e6f994b2e5a5593313c1);	
        
        NODE_SET_METHOD(exports, "lh_strhash", F00870b23e2f1aa2d60f1077afe068779905a6b7c);	
        
        NODE_SET_METHOD(exports, "OBJ_NAME_cleanup", Fe62a0fb5ea4a4e3d441f82264e8f419b64f83df1);	
        
        NODE_SET_METHOD(exports, "ERR_error_string", Fb8320143fb66752b5acf0749720e917aacf0fdae);	
        
        NODE_SET_METHOD(exports, "parse_yesno", F0343cc72d1404268343721d3f392bf214d3b2d97);	
        
        NODE_SET_METHOD(exports, "BIO_new_file", F04b160c04b6b047e2c95ae53e03f14237bf56cc1);	
        
        NODE_SET_METHOD(exports, "EVP_PKEY_asn1_get0", Fc094fb7d243ebfdff2012fb323e0ac1ceb055840);	
        
        NODE_SET_METHOD(exports, "ASN1_STRING_TABLE_get", F45a6c15bf8aebed2bd07660d26d6410f7995cab7);	
        
        NODE_SET_METHOD(exports, "pem_check_suffix", Fcae7001bca697e1ebc6593e5f07670a4ff0557e9);	
        
        NODE_SET_METHOD(exports, "ERR_remove_state", F43e54da7587da68b838b74d471d51027bfc4d9d2);	
        
        NODE_SET_METHOD(exports, "UI_create_method", F2905eaf84829553f109d69cd0e8e3cbb3db4a9ad);	
        
        NODE_SET_METHOD(exports, "OBJ_nid2obj", F9c15cea8f4734fadc396ec0b90726dea1f149644);	
        
        NODE_SET_METHOD(exports, "SSL_alert_type_string_long", Fa64c4183ebf34775e342b7db8f185e53224092c9);	
        
        NODE_SET_METHOD(exports, "CRYPTO_set_mem_debug_options", F076dd4e443ac7604a639be4dcafce7ed8642edfc);	
        
        NODE_SET_METHOD(exports, "OBJ_sn2nid", F04ca27d2727d2f59cac0bf37b440d9072fc6b7cc);	
        
        NODE_SET_METHOD(exports, "RAND_egd_bytes", Ff5bfae44e404ecab5babcaa9a9868dbf2843a5e3);	
        
        NODE_SET_METHOD(exports, "BIO_sock_non_fatal_error", F28e7ab0aff8acd1488479d8e3d3684a65f3a3e48);	
        
        NODE_SET_METHOD(exports, "OpenSSLDie", F300d5d9f4acaa96a3e19b5c5b7cd0751217d8999);	
        
        NODE_SET_METHOD(exports, "EC_KEY_new_by_curve_name", F6b51b926459b8d06ce56f207d0eac23f1cb48e3f);	
        
        NODE_SET_METHOD(exports, "ssl_bad_method", F843a70847ed7f94a5050e239388247fe2f51a70e);	
        
        NODE_SET_METHOD(exports, "BUF_strdup", Fb1bd9e6bb5c712af29fb86024e274d36728dde60);	
        
        NODE_SET_METHOD(exports, "EC_GROUP_new_by_curve_name", Fa870d3ec6367b211d530e84081789035e48d9f53);	
        
        NODE_SET_METHOD(exports, "ERR_reason_error_string", Faeafccd98c1a29b1a43d7c8263d95a4c09b04bf6);	
        
        NODE_SET_METHOD(exports, "tls12_get_hash", Ffcb6e9345977648c45c5a9b507cd74bc77095caa);	
        
        NODE_SET_METHOD(exports, "dtls1_get_queue_priority", F9a51bb8b7186ea32ad6c2a1a2106107e4c355c0c);	
        
        NODE_SET_METHOD(exports, "CRYPTO_get_dynlock_value", Fdd13e1e75414735910056181e4243b15290c2499);	
        
        NODE_SET_METHOD(exports, "tls1_alert_code", F465d2b978111476900f8a0851870c20ed035a795);	
        
        NODE_SET_METHOD(exports, "BUF_strlcpy", F505571b978dcbfbec6f2cdaeccfec3ef04e1ed49);	
        
        NODE_SET_METHOD(exports, "X509_VERIFY_PARAM_lookup", Fb818030be70dd7462e11aaf7abc7a28fe1962153);	
        
        NODE_SET_METHOD(exports, "X509_PURPOSE_get_by_id", Fd063720e4cb29e6e6794c4d5d367c5bbaa9033d9);	
        
        NODE_SET_METHOD(exports, "ENGINE_get_digest_engine", Fbdad082abdb69c313ff040a65e4cdb08e3107677);	
        
        NODE_SET_METHOD(exports, "X509V3_EXT_get_nid", F4c5bbe1a85b8b8a9ba3fee167c5678edcc316ffd);	
        
        NODE_SET_METHOD(exports, "CRYPTO_push_info_", F6c398d138afb6fff67fa2c9182946d3383fb4866);	
        
        NODE_SET_METHOD(exports, "DSO_global_lookup", Fd2535c701d4e09f548989a3ef86a6c6f3c03604b);	
        
        NODE_SET_METHOD(exports, "SRP_get_default_gN", F608b32cfaab5c93dc4c7b4954dcc6e85029bd4cf);	
        
        NODE_SET_METHOD(exports, "ENGINE_get_pkey_meth_engine", Fa7fb86003a76e2553bbe57b40b699db72353a4e3);	
        
        NODE_SET_METHOD(exports, "CRYPTO_get_lock_name", F22e38a1127e5dd20729c4c7385dd313a74875195);	
        
        NODE_SET_METHOD(exports, "SSL_alert_desc_string", F378f1050c368e5bb809952a4babce43fa6ed3fa1);	
        
        NODE_SET_METHOD(exports, "a2i_IPADDRESS", Ff6c3c1e8c7585e606feaa1c1ebda69e590491bbd);	
        
        NODE_SET_METHOD(exports, "EVP_set_pw_prompt", F553e95e7d0d11368328c693892132ed32c6bde8e);	
        
        NODE_SET_METHOD(exports, "rotate_serial", F3a6de72dc6a9231821fdd1857ef99fe8fc2479e5);	
        
        NODE_SET_METHOD(exports, "EVP_read_pw_string", Fd6d0e1643d32c580ed02aabfed4eea7a31259821);	
        
        NODE_SET_METHOD(exports, "EVP_get_digestbyname", Ff13bbe52960485801a22bca127731aff6571ea00);	
        
        NODE_SET_METHOD(exports, "OBJ_new_nid", F5b0f88f7b3515766bc77c5e2b3538917d3ae50ba);	
        
        NODE_SET_METHOD(exports, "RAND_egd", F7741397c54505522901b321d04a0f0181d96bd87);	
        
        NODE_SET_METHOD(exports, "ERR_func_error_string", Fb7fd0942506396403329e499416c8145d21fff8d);	
        
        NODE_SET_METHOD(exports, "OBJ_nid2sn", Fdbaa8d10bfcc89f27e7c15dc93e9b2cb148c8a9e);	
        
        NODE_SET_METHOD(exports, "ERR_error_string_n", Feb3e496e35232aeb5b7ead4d6e2fd112e0c8bcb0);	
        
        NODE_SET_METHOD(exports, "a2i_IPADDRESS_NC", F52b8b0b795b676bc9472876c6e75152d885aacdc);	
        
        NODE_SET_METHOD(exports, "CRYPTO_dbg_set_options", F82335ac28b86f5ea26de5c171cdd936789beda08);	
        
        NODE_SET_METHOD(exports, "app_init", F6cef3c719d5773777c1f415016dcb77c817d8e08);	
        
        NODE_SET_METHOD(exports, "bn_div_words", F18ad0ab09eabd710082995c5427ba3efc36bc21a);	
        
        NODE_SET_METHOD(exports, "CRYPTO_strdup", Fd6b01b638bdc9193db96414949f5a27d34b814c6);	
        
        NODE_SET_METHOD(exports, "EVP_PKEY_asn1_add_alias", F1375428682ae931890b9506be00b036dd3cd6a9b);	
        
        NODE_SET_METHOD(exports, "CRYPTO_malloc_locked", F35210f71d91dd9633ef15f6c0423b32acf77b808);	
        
        NODE_SET_METHOD(exports, "EVP_read_pw_string_min", F8af6f76675040e8c7615369e0de9e87c86429df5);	
        
        NODE_SET_METHOD(exports, "rotate_index", Ff75ea5a2a99da9e296edd68fb96d7c2ed5406f76);	
        
        NODE_SET_METHOD(exports, "app_tminterval", F5b335a8cd08cdcf4ab52edac09273384629f1d81);	
        
        NODE_SET_METHOD(exports, "PEM_proc_type", F9ebf465984b4d3d462df0a85efc1d1a57dd366e1);	
        
        NODE_SET_METHOD(exports, "ENGINE_set_table_flags", Ffc3eae03b7c6147bf704a41143b3201aac8e678b);	
        
        NODE_SET_METHOD(exports, "ASN1_STRING_type_new", Fee3438b457610e881d1a76fabc55c781cb12f60a);	
        
        NODE_SET_METHOD(exports, "ENGINE_get_cipher_engine", Ff99cd567e7c2229386d56a60def3b18335e66f45);	
        
        NODE_SET_METHOD(exports, "X509_TRUST_get_by_id", F1a0ad24f960f06ef6bb0504fedc40939c73b5924);	
        
        NODE_SET_METHOD(exports, "RSA_X931_hash_id", Faa02fdc38bd323a2509f2aee2cd527139090d38b);	
        
        NODE_SET_METHOD(exports, "SRP_VBASE_new", F4712dea9ac1fbf1aca226ba1ba0856973b00880b);	
        
        NODE_SET_METHOD(exports, "OBJ_txt2nid", F95518f2242375dacb0a81acf93538e2357043b1e);	
        
        NODE_SET_METHOD(exports, "BIO_sock_should_retry", Fbba77e6a898ffb5603d4cd5222a8baff6e48154c);	
        
        NODE_SET_METHOD(exports, "app_RAND_load_files", Fb88a76850c4eca4c72763b708392a3e8912feb41);	
        
        NODE_SET_METHOD(exports, "X509_PURPOSE_get0", F4e7b9aef1fb091f2fdba85081fe6d2f9641fb234);	
        
        NODE_SET_METHOD(exports, "CRYPTO_lock", F16f7edcd1a50c072c57dfb946cfd71b01b6135b5);	
        
        NODE_SET_METHOD(exports, "ENGINE_get_pkey_asn1_meth_engine", Fa76e0fccaf363a0e1497edba0fb8dc01118d5679);	
        
        NODE_SET_METHOD(exports, "X509_REQ_extension_nid", Fbaa47876d40e51082bc810e6fd6d1762a5bb1e67);	
        
        NODE_SET_METHOD(exports, "ASN1_STRING_TABLE_add", F038b95ea39c67b844ab65dc0a780f70cae7e6c2a);	
        
        NODE_SET_METHOD(exports, "ERR_lib_error_string", F7b8024edd2cb6c3f1cc8078f7ef45be917f629cb);	
        
        NODE_SET_METHOD(exports, "OBJ_add_sigid", F4d4414daaba1955bbf79d269e1b7ba839cdc9ca4);	
        
        NODE_SET_METHOD(exports, "CONF_modules_unload", Ff6d2c477c7f13e1e899f957615eb749dbd57b8d6);	
        
        NODE_SET_METHOD(exports, "ASN1_object_size", F8d6a9fe332e35d8a57ac25a353245f25c512003e);	
        
        NODE_SET_METHOD(exports, "parse_name", F4329736e1589184872835a4f98db8eb5af70fbf7);	
        
        NODE_SET_METHOD(exports, "PEM_dek_info", F37a306f689a08e7c2e1e17eab539f5be6e77b66e);	
        
        NODE_SET_METHOD(exports, "ASN1_STRING_set_default_mask", Fc036a5579c62496353b3324cb8602a237939e243);	
        
        NODE_SET_METHOD(exports, "name_cmp", F9b78f1f5586a6d31329c27fc8c37cbba8cea1970);	
        
        NODE_SET_METHOD(exports, "OBJ_NAME_get", F0ee2a72b66ef5ee7d90c8adbaa3d80ecaff3c6db);	
        
        NODE_SET_METHOD(exports, "BN_set_params", F041b27d285caa212cbb08c4035c69451a07ef25f);	
        
        NODE_SET_METHOD(exports, "ASN1_tag2bit", F9317c7310716ce636e0ea3c84e4161f09b046621);	
        
        NODE_SET_METHOD(exports, "ssl23_get_cipher", F7f9cfc39e7a1e02a02d3d84aa3e661496aa80224);	
        
        NODE_SET_METHOD(exports, "tls1_ec_nid2curve_id", F8ac4c09b073ffc7e7aee718460a3aa90ad6c1ad4);	
        
        NODE_SET_METHOD(exports, "SSL_alert_type_string", Fd2b196423662824548125de52937919264c5a553);	
        
        NODE_SET_METHOD(exports, "BUF_strndup", F08e08b0ce3ff218c6ea2ff98d7de97554a0582b3);	
        
        NODE_SET_METHOD(exports, "X509V3_parse_list", F4d10e764b76687a6c390fc019a1bec479ca241c1);	
        
        NODE_SET_METHOD(exports, "OBJ_txt2obj", F9261d350d6293b95eff793a0e4b54077167908df);	
        
        NODE_SET_METHOD(exports, "tls1_ec_curve_id2nid", F3ffbd77e38b703ce0b310326a92bcfc6fad31ea2);	
        
        NODE_SET_METHOD(exports, "SSL_alert_desc_string_long", F067a0c4bb134af4744afce63433406e7c80394c2);	
        
        NODE_SET_METHOD(exports, "OBJ_create", F178c7c8f9a31ec105b74563bf462289171172284);	
        
        NODE_SET_METHOD(exports, "program_name", F0acd9799353eb07afc0dd218536343cd3434980c);	
        
        NODE_SET_METHOD(exports, "FuzzerEntrypoint", F7edcf1f0d8c089d919e1bcd8c0f8603303446385);	
        
        NODE_SET_METHOD(exports, "ASN1_STRING_set_default_mask_asc", Ffd174d30c2aedff651e9d313705f98d503d5c5d0);	
        
        NODE_SET_METHOD(exports, "ERR_put_error", Fa6dd7e91f8d016443706dd74439d19194164225f);	
        
        NODE_SET_METHOD(exports, "OBJ_ln2nid", F0bd060e375f198fcd8462888f79e6edf7387a4c5);	
        
        NODE_SET_METHOD(exports, "ssl_verify_alarm_type", Fccbaf4004fbbf38aeb34e3681f34a6688e047716);	
        
        NODE_SET_METHOD(exports, "CRYPTO_mem_ctrl", F3535a390f029534b7299ab3d55ef37fb80ed7c5c);	
        
        NODE_SET_METHOD(exports, "EVP_get_cipherbyname", F2419add76f8cd55715547acc4402a815fa0eeb4a);	
        
        NODE_SET_METHOD(exports, "OBJ_nid2ln", F6547564823d8009aca81830335e18b7737d66dca);	
        
        NODE_SET_METHOD(exports, "BIO_new_socket", F2562d216df5ea9122a08251a0b1087b472bfdec8);	
        
        NODE_SET_METHOD(exports, "ENGINE_by_id", F9bdd83dd17fa8f01e7fe2753a8f0b0cd945805ef);	
        
}

NODE_MODULE(NODE_GYP_MODULE_NAME, Initialize)
#endif
} // namespace v8glue
