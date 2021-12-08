#!/usr/bin/env ts-node


import * as fb from "bex/fb";
import * as body from "bex/body";
import * as bh from "bex/byte_helpers";
import * as v8glue from "./v8glue";


fb.init();
const rng = fb.DefaultRNG();



// int X509V3_EXT_add_alias(int, int)

let gen47 = new fb.Generator("X509V3_EXT_add_alias", rng);




gen47.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));









gen47.addField(new fb.Integer("arg1", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen47.addSensor(new fb.Sensor8BitCounter("8bit"));
gen47.addSensor(new fb.SensorComparison("comparison"));



const gen47Body = (gen: fb.Generator) => {
    v8glue.X509V3_EXT_add_alias(
	
	
	gen.getField("arg0").value
	
	, 
	gen.getField("arg1").value
	
    );
};

export function Ff5c353af12e050f9b075655f13344c90cfbfb835 () {
    body.Fuzzer("gen47", gen47, gen47Body, v8glue, rng);
}


// int OBJ_NAME_remove(const char *, int)

let gen68 = new fb.Generator("OBJ_NAME_remove", rng);




gen68.addField(new fb.Integer("arg1", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));













gen68.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen68.addSensor(new fb.Sensor8BitCounter("8bit"));
gen68.addSensor(new fb.SensorComparison("comparison"));



const gen68Body = (gen: fb.Generator) => {
    v8glue.OBJ_NAME_remove(
	
	
	bh.ToString(gen.getField("arg0").value)
	
	, 
	gen.getField("arg1").value
	
    );
};

export function Fbdde52fc0aa3122703e226e66355688b4eba7376 () {
    body.Fuzzer("gen68", gen68, gen68Body, v8glue, rng);
}


// int X509_PURPOSE_get_by_sname(char *)

let gen76 = new fb.Generator("X509_PURPOSE_get_by_sname", rng);








gen76.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen76.addSensor(new fb.Sensor8BitCounter("8bit"));
gen76.addSensor(new fb.SensorComparison("comparison"));



const gen76Body = (gen: fb.Generator) => {
    v8glue.X509_PURPOSE_get_by_sname(
	
	
	bh.ToString(gen.getField("arg0").value)
	
    );
};

export function Ff6e9941f5fdf360fc1fc2e9410a72bb53cb23bc3 () {
    body.Fuzzer("gen76", gen76, gen76Body, v8glue, rng);
}


// int OBJ_NAME_add(const char *, int, const char *)

let gen97 = new fb.Generator("OBJ_NAME_add", rng);




gen97.addField(new fb.Integer("arg1", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));













gen97.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());









gen97.addField(new fb.ByteArray("arg2", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen97.addSensor(new fb.Sensor8BitCounter("8bit"));
gen97.addSensor(new fb.SensorComparison("comparison"));



const gen97Body = (gen: fb.Generator) => {
    v8glue.OBJ_NAME_add(
	
	
	bh.ToString(gen.getField("arg0").value)
	
	, 
	gen.getField("arg1").value
	
	, 
	bh.ToString(gen.getField("arg2").value)
	
    );
};

export function F6540b5cec98edbaa65a07f5435a2f19792cdf4ef () {
    body.Fuzzer("gen97", gen97, gen97Body, v8glue, rng);
}


// char *make_revocation_str(int, char *)

let gen123 = new fb.Generator("make_revocation_str", rng);




gen123.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));













gen123.addField(new fb.ByteArray("arg1", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen123.addSensor(new fb.Sensor8BitCounter("8bit"));
gen123.addSensor(new fb.SensorComparison("comparison"));



const gen123Body = (gen: fb.Generator) => {
    v8glue.make_revocation_str(
	
	
	gen.getField("arg0").value
	
	, 
	bh.ToString(gen.getField("arg1").value)
	
    );
};

export function Fab452aae83fdb7543bcdbcce8234adc0869cd97e () {
    body.Fuzzer("gen123", gen123, gen123Body, v8glue, rng);
}


// struct stack_st_X509_NAME *SSL_load_client_CA_file(const char *)

let gen129 = new fb.Generator("SSL_load_client_CA_file", rng);








gen129.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen129.addSensor(new fb.Sensor8BitCounter("8bit"));
gen129.addSensor(new fb.SensorComparison("comparison"));



const gen129Body = (gen: fb.Generator) => {
    v8glue.SSL_load_client_CA_file(
	
	
	bh.ToString(gen.getField("arg0").value)
	
    );
};

export function F5c9f55f0750024d45ac6dd88f01add42be330ff0 () {
    body.Fuzzer("gen129", gen129, gen129Body, v8glue, rng);
}


// int CONF_modules_load_file(const char *, const char *, unsigned long)

let gen141 = new fb.Generator("CONF_modules_load_file", rng);




gen141.addField(new fb.Integer("arg2", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(0), BigInt("18446744073709551616")));













gen141.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());









gen141.addField(new fb.ByteArray("arg1", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen141.addSensor(new fb.Sensor8BitCounter("8bit"));
gen141.addSensor(new fb.SensorComparison("comparison"));



const gen141Body = (gen: fb.Generator) => {
    v8glue.CONF_modules_load_file(
	
	
	bh.ToString(gen.getField("arg0").value)
	
	, 
	bh.ToString(gen.getField("arg1").value)
	
	, 
	gen.getField("arg2").value
	
    );
};

export function Fa561a51799a68a95f687e8189e1f15f5319834ea () {
    body.Fuzzer("gen141", gen141, gen141Body, v8glue, rng);
}


// const char *ASN1_tag2str(int)

let gen144 = new fb.Generator("ASN1_tag2str", rng);




gen144.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen144.addSensor(new fb.Sensor8BitCounter("8bit"));
gen144.addSensor(new fb.SensorComparison("comparison"));



const gen144Body = (gen: fb.Generator) => {
    v8glue.ASN1_tag2str(
	
	
	gen.getField("arg0").value
	
    );
};

export function F22354db8a27cb2263d0a119c7d9c88cf86442fe9 () {
    body.Fuzzer("gen144", gen144, gen144Body, v8glue, rng);
}


// int app_isdir(const char *)

let gen203 = new fb.Generator("app_isdir", rng);








gen203.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen203.addSensor(new fb.Sensor8BitCounter("8bit"));
gen203.addSensor(new fb.SensorComparison("comparison"));



const gen203Body = (gen: fb.Generator) => {
    v8glue.app_isdir(
	
	
	bh.ToString(gen.getField("arg0").value)
	
    );
};

export function F91aa3575215ce93743ed6c84f693423850887d8b () {
    body.Fuzzer("gen203", gen203, gen203Body, v8glue, rng);
}


// void check_defer(int)

let gen211 = new fb.Generator("check_defer", rng);




gen211.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen211.addSensor(new fb.Sensor8BitCounter("8bit"));
gen211.addSensor(new fb.SensorComparison("comparison"));



const gen211Body = (gen: fb.Generator) => {
    v8glue.check_defer(
	
	
	gen.getField("arg0").value
	
    );
};

export function F967eb4e00b6b220c4986e65dd50c8d6746dfc586 () {
    body.Fuzzer("gen211", gen211, gen211Body, v8glue, rng);
}


// int str2fmt(char *)

let gen252 = new fb.Generator("str2fmt", rng);








gen252.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen252.addSensor(new fb.Sensor8BitCounter("8bit"));
gen252.addSensor(new fb.SensorComparison("comparison"));



const gen252Body = (gen: fb.Generator) => {
    v8glue.str2fmt(
	
	
	bh.ToString(gen.getField("arg0").value)
	
    );
};

export function F91dd22988f5e3fe5d6b7f474d898b6679d55382a () {
    body.Fuzzer("gen252", gen252, gen252Body, v8glue, rng);
}


// int BN_num_bits_word(unsigned long)

let gen260 = new fb.Generator("BN_num_bits_word", rng);




gen260.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(0), BigInt("18446744073709551616")));








gen260.addSensor(new fb.Sensor8BitCounter("8bit"));
gen260.addSensor(new fb.SensorComparison("comparison"));



const gen260Body = (gen: fb.Generator) => {
    v8glue.BN_num_bits_word(
	
	
	gen.getField("arg0").value
	
    );
};

export function Fe9c2e889e8cb007b9397686f9ddf68fbb432ded7 () {
    body.Fuzzer("gen260", gen260, gen260Body, v8glue, rng);
}


// struct evp_pkey_asn1_method_st *EVP_PKEY_asn1_new(int, int, const char *, const char *)

let gen320 = new fb.Generator("EVP_PKEY_asn1_new", rng);




gen320.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));









gen320.addField(new fb.Integer("arg1", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));













gen320.addField(new fb.ByteArray("arg2", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());









gen320.addField(new fb.ByteArray("arg3", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen320.addSensor(new fb.Sensor8BitCounter("8bit"));
gen320.addSensor(new fb.SensorComparison("comparison"));



const gen320Body = (gen: fb.Generator) => {
    v8glue.EVP_PKEY_asn1_new(
	
	
	gen.getField("arg0").value
	
	, 
	gen.getField("arg1").value
	
	, 
	bh.ToString(gen.getField("arg2").value)
	
	, 
	bh.ToString(gen.getField("arg3").value)
	
    );
};

export function Fd99514fde33712a8cafc36f61288dcb9d2979600 () {
    body.Fuzzer("gen320", gen320, gen320Body, v8glue, rng);
}


// int BN_get_params(int)

let gen371 = new fb.Generator("BN_get_params", rng);




gen371.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen371.addSensor(new fb.Sensor8BitCounter("8bit"));
gen371.addSensor(new fb.SensorComparison("comparison"));



const gen371Body = (gen: fb.Generator) => {
    v8glue.BN_get_params(
	
	
	gen.getField("arg0").value
	
    );
};

export function F03570939aff17c4c5b100ca90efd3546d24ec2e5 () {
    body.Fuzzer("gen371", gen371, gen371Body, v8glue, rng);
}


// void *CRYPTO_malloc(int, const char *, int)

let gen378 = new fb.Generator("CRYPTO_malloc", rng);




gen378.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));









gen378.addField(new fb.Integer("arg2", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));













gen378.addField(new fb.ByteArray("arg1", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen378.addSensor(new fb.Sensor8BitCounter("8bit"));
gen378.addSensor(new fb.SensorComparison("comparison"));



const gen378Body = (gen: fb.Generator) => {
    v8glue.CRYPTO_malloc(
	
	
	gen.getField("arg0").value
	
	, 
	bh.ToString(gen.getField("arg1").value)
	
	, 
	gen.getField("arg2").value
	
    );
};

export function F3f891508b4018fdbdc77c5a8a94b52efa6c44866 () {
    body.Fuzzer("gen378", gen378, gen378Body, v8glue, rng);
}


// struct evp_pkey_method_st *EVP_PKEY_meth_new(int, int)

let gen399 = new fb.Generator("EVP_PKEY_meth_new", rng);




gen399.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));









gen399.addField(new fb.Integer("arg1", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen399.addSensor(new fb.Sensor8BitCounter("8bit"));
gen399.addSensor(new fb.SensorComparison("comparison"));



const gen399Body = (gen: fb.Generator) => {
    v8glue.EVP_PKEY_meth_new(
	
	
	gen.getField("arg0").value
	
	, 
	gen.getField("arg1").value
	
    );
};

export function F9007108531962d8f270c746313eaa03b341109ea () {
    body.Fuzzer("gen399", gen399, gen399Body, v8glue, rng);
}


// const struct evp_pkey_method_st *EVP_PKEY_meth_find(int)

let gen403 = new fb.Generator("EVP_PKEY_meth_find", rng);




gen403.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen403.addSensor(new fb.Sensor8BitCounter("8bit"));
gen403.addSensor(new fb.SensorComparison("comparison"));



const gen403Body = (gen: fb.Generator) => {
    v8glue.EVP_PKEY_meth_find(
	
	
	gen.getField("arg0").value
	
    );
};

export function Fe97ff9adb5bfb7bb500c2224d30832aab6fffabd () {
    body.Fuzzer("gen403", gen403, gen403Body, v8glue, rng);
}


// int CRYPTO_get_new_lockid(char *)

let gen408 = new fb.Generator("CRYPTO_get_new_lockid", rng);








gen408.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen408.addSensor(new fb.Sensor8BitCounter("8bit"));
gen408.addSensor(new fb.SensorComparison("comparison"));



const gen408Body = (gen: fb.Generator) => {
    v8glue.CRYPTO_get_new_lockid(
	
	
	bh.ToString(gen.getField("arg0").value)
	
    );
};

export function F98402ab8e1e9be0331fe309fc933b90a712de7be () {
    body.Fuzzer("gen408", gen408, gen408Body, v8glue, rng);
}


// const struct ssl_cipher_st *ssl2_get_cipher(unsigned int)

let gen479 = new fb.Generator("ssl2_get_cipher", rng);




gen479.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(0), BigInt(4294967296)));








gen479.addSensor(new fb.Sensor8BitCounter("8bit"));
gen479.addSensor(new fb.SensorComparison("comparison"));



const gen479Body = (gen: fb.Generator) => {
    v8glue.ssl2_get_cipher(
	
	
	gen.getField("arg0").value
	
    );
};

export function Fe8a6e624890d1d016813ea8da358c65e00d095b4 () {
    body.Fuzzer("gen479", gen479, gen479Body, v8glue, rng);
}


// struct x509_trust_st *X509_TRUST_get0(int)

let gen491 = new fb.Generator("X509_TRUST_get0", rng);




gen491.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen491.addSensor(new fb.Sensor8BitCounter("8bit"));
gen491.addSensor(new fb.SensorComparison("comparison"));



const gen491Body = (gen: fb.Generator) => {
    v8glue.X509_TRUST_get0(
	
	
	gen.getField("arg0").value
	
    );
};

export function F04ac48616804a41d5cf31f9d5b1f4c69d66b7cab () {
    body.Fuzzer("gen491", gen491, gen491Body, v8glue, rng);
}


// int EVP_PKEY_type(int)

let gen499 = new fb.Generator("EVP_PKEY_type", rng);




gen499.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen499.addSensor(new fb.Sensor8BitCounter("8bit"));
gen499.addSensor(new fb.SensorComparison("comparison"));



const gen499Body = (gen: fb.Generator) => {
    v8glue.EVP_PKEY_type(
	
	
	gen.getField("arg0").value
	
    );
};

export function Feab34d6bd1e1908270a948da4619c990a70b637f () {
    body.Fuzzer("gen499", gen499, gen499Body, v8glue, rng);
}


// unsigned long BUF_strlcat(char *, const char *, unsigned long)

let gen533 = new fb.Generator("BUF_strlcat", rng);



gen533.addField(new fb.ByteArray("arg1", 4096, rng))
	.addDefaultMutators()








gen533.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen533.addSensor(new fb.Sensor8BitCounter("8bit"));
gen533.addSensor(new fb.SensorComparison("comparison"));



const gen533Body = (gen: fb.Generator) => {
    v8glue.BUF_strlcat(
	
	
	bh.ToString(gen.getField("arg0").value)
	
	, 
	gen.getField("arg1").value
	
	, 
	undefined
	
    );
};

export function F35b2579c7dc1055c655c2cd192ba9d74637eead7 () {
    body.Fuzzer("gen533", gen533, gen533Body, v8glue, rng);
}


// const struct ssl_cipher_st *dtls1_get_cipher(unsigned int)

let gen537 = new fb.Generator("dtls1_get_cipher", rng);




gen537.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(0), BigInt(4294967296)));








gen537.addSensor(new fb.Sensor8BitCounter("8bit"));
gen537.addSensor(new fb.SensorComparison("comparison"));



const gen537Body = (gen: fb.Generator) => {
    v8glue.dtls1_get_cipher(
	
	
	gen.getField("arg0").value
	
    );
};

export function F178db9e12c3140d00dddd2e60fc5d17b9a15e50d () {
    body.Fuzzer("gen537", gen537, gen537Body, v8glue, rng);
}


// void CRYPTO_destroy_dynlockid(int)

let gen550 = new fb.Generator("CRYPTO_destroy_dynlockid", rng);




gen550.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen550.addSensor(new fb.Sensor8BitCounter("8bit"));
gen550.addSensor(new fb.SensorComparison("comparison"));



const gen550Body = (gen: fb.Generator) => {
    v8glue.CRYPTO_destroy_dynlockid(
	
	
	gen.getField("arg0").value
	
    );
};

export function F96ce81ead890005724e32baeb740fbf1e72491e7 () {
    body.Fuzzer("gen550", gen550, gen550Body, v8glue, rng);
}


// int ssl3_alert_code(int)

let gen553 = new fb.Generator("ssl3_alert_code", rng);




gen553.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen553.addSensor(new fb.Sensor8BitCounter("8bit"));
gen553.addSensor(new fb.SensorComparison("comparison"));



const gen553Body = (gen: fb.Generator) => {
    v8glue.ssl3_alert_code(
	
	
	gen.getField("arg0").value
	
    );
};

export function Fcd5bbec33510a2bb830434212b280b3a8eba747f () {
    body.Fuzzer("gen553", gen553, gen553Body, v8glue, rng);
}


// const struct ssl_cipher_st *ssl3_get_cipher(unsigned int)

let gen615 = new fb.Generator("ssl3_get_cipher", rng);




gen615.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(0), BigInt(4294967296)));








gen615.addSensor(new fb.Sensor8BitCounter("8bit"));
gen615.addSensor(new fb.SensorComparison("comparison"));



const gen615Body = (gen: fb.Generator) => {
    v8glue.ssl3_get_cipher(
	
	
	gen.getField("arg0").value
	
    );
};

export function Fd377300718c7787d1951b8305c6b43dab0e55d1a () {
    body.Fuzzer("gen615", gen615, gen615Body, v8glue, rng);
}


// void ERR_set_error_data(char *, int)

let gen626 = new fb.Generator("ERR_set_error_data", rng);




gen626.addField(new fb.Integer("arg1", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));













gen626.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen626.addSensor(new fb.Sensor8BitCounter("8bit"));
gen626.addSensor(new fb.SensorComparison("comparison"));



const gen626Body = (gen: fb.Generator) => {
    v8glue.ERR_set_error_data(
	
	
	bh.ToString(gen.getField("arg0").value)
	
	, 
	gen.getField("arg1").value
	
    );
};

export function Fbca24acef13389fa41f1e6f994b2e5a5593313c1 () {
    body.Fuzzer("gen626", gen626, gen626Body, v8glue, rng);
}


// unsigned long lh_strhash(const char *)

let gen713 = new fb.Generator("lh_strhash", rng);








gen713.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen713.addSensor(new fb.Sensor8BitCounter("8bit"));
gen713.addSensor(new fb.SensorComparison("comparison"));



const gen713Body = (gen: fb.Generator) => {
    v8glue.lh_strhash(
	
	
	bh.ToString(gen.getField("arg0").value)
	
    );
};

export function F00870b23e2f1aa2d60f1077afe068779905a6b7c () {
    body.Fuzzer("gen713", gen713, gen713Body, v8glue, rng);
}


// void OBJ_NAME_cleanup(int)

let gen742 = new fb.Generator("OBJ_NAME_cleanup", rng);




gen742.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen742.addSensor(new fb.Sensor8BitCounter("8bit"));
gen742.addSensor(new fb.SensorComparison("comparison"));



const gen742Body = (gen: fb.Generator) => {
    v8glue.OBJ_NAME_cleanup(
	
	
	gen.getField("arg0").value
	
    );
};

export function Fe62a0fb5ea4a4e3d441f82264e8f419b64f83df1 () {
    body.Fuzzer("gen742", gen742, gen742Body, v8glue, rng);
}


// char *ERR_error_string(unsigned long, char *)

let gen757 = new fb.Generator("ERR_error_string", rng);




gen757.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(0), BigInt("18446744073709551616")));













gen757.addField(new fb.ByteArray("arg1", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen757.addSensor(new fb.Sensor8BitCounter("8bit"));
gen757.addSensor(new fb.SensorComparison("comparison"));



const gen757Body = (gen: fb.Generator) => {
    v8glue.ERR_error_string(
	
	
	gen.getField("arg0").value
	
	, 
	bh.ToString(gen.getField("arg1").value)
	
    );
};

export function Fb8320143fb66752b5acf0749720e917aacf0fdae () {
    body.Fuzzer("gen757", gen757, gen757Body, v8glue, rng);
}


// int parse_yesno(const char *, int)

let gen766 = new fb.Generator("parse_yesno", rng);




gen766.addField(new fb.Integer("arg1", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));













gen766.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen766.addSensor(new fb.Sensor8BitCounter("8bit"));
gen766.addSensor(new fb.SensorComparison("comparison"));



const gen766Body = (gen: fb.Generator) => {
    v8glue.parse_yesno(
	
	
	bh.ToString(gen.getField("arg0").value)
	
	, 
	gen.getField("arg1").value
	
    );
};

export function F0343cc72d1404268343721d3f392bf214d3b2d97 () {
    body.Fuzzer("gen766", gen766, gen766Body, v8glue, rng);
}


// struct bio_st *BIO_new_file(const char *, const char *)

let gen771 = new fb.Generator("BIO_new_file", rng);








gen771.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());









gen771.addField(new fb.ByteArray("arg1", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen771.addSensor(new fb.Sensor8BitCounter("8bit"));
gen771.addSensor(new fb.SensorComparison("comparison"));



const gen771Body = (gen: fb.Generator) => {
    v8glue.BIO_new_file(
	
	
	bh.ToString(gen.getField("arg0").value)
	
	, 
	bh.ToString(gen.getField("arg1").value)
	
    );
};

export function F04b160c04b6b047e2c95ae53e03f14237bf56cc1 () {
    body.Fuzzer("gen771", gen771, gen771Body, v8glue, rng);
}


// const struct evp_pkey_asn1_method_st *EVP_PKEY_asn1_get0(int)

let gen777 = new fb.Generator("EVP_PKEY_asn1_get0", rng);




gen777.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen777.addSensor(new fb.Sensor8BitCounter("8bit"));
gen777.addSensor(new fb.SensorComparison("comparison"));



const gen777Body = (gen: fb.Generator) => {
    v8glue.EVP_PKEY_asn1_get0(
	
	
	gen.getField("arg0").value
	
    );
};

export function Fc094fb7d243ebfdff2012fb323e0ac1ceb055840 () {
    body.Fuzzer("gen777", gen777, gen777Body, v8glue, rng);
}


// struct asn1_string_table_st *ASN1_STRING_TABLE_get(int)

let gen787 = new fb.Generator("ASN1_STRING_TABLE_get", rng);




gen787.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen787.addSensor(new fb.Sensor8BitCounter("8bit"));
gen787.addSensor(new fb.SensorComparison("comparison"));



const gen787Body = (gen: fb.Generator) => {
    v8glue.ASN1_STRING_TABLE_get(
	
	
	gen.getField("arg0").value
	
    );
};

export function F45a6c15bf8aebed2bd07660d26d6410f7995cab7 () {
    body.Fuzzer("gen787", gen787, gen787Body, v8glue, rng);
}


// int pem_check_suffix(const char *, const char *)

let gen849 = new fb.Generator("pem_check_suffix", rng);








gen849.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());









gen849.addField(new fb.ByteArray("arg1", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen849.addSensor(new fb.Sensor8BitCounter("8bit"));
gen849.addSensor(new fb.SensorComparison("comparison"));



const gen849Body = (gen: fb.Generator) => {
    v8glue.pem_check_suffix(
	
	
	bh.ToString(gen.getField("arg0").value)
	
	, 
	bh.ToString(gen.getField("arg1").value)
	
    );
};

export function Fcae7001bca697e1ebc6593e5f07670a4ff0557e9 () {
    body.Fuzzer("gen849", gen849, gen849Body, v8glue, rng);
}


// void ERR_remove_state(unsigned long)

let gen904 = new fb.Generator("ERR_remove_state", rng);




gen904.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(0), BigInt("18446744073709551616")));








gen904.addSensor(new fb.Sensor8BitCounter("8bit"));
gen904.addSensor(new fb.SensorComparison("comparison"));



const gen904Body = (gen: fb.Generator) => {
    v8glue.ERR_remove_state(
	
	
	gen.getField("arg0").value
	
    );
};

export function F43e54da7587da68b838b74d471d51027bfc4d9d2 () {
    body.Fuzzer("gen904", gen904, gen904Body, v8glue, rng);
}


// struct ui_method_st *UI_create_method(char *)

let gen934 = new fb.Generator("UI_create_method", rng);








gen934.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen934.addSensor(new fb.Sensor8BitCounter("8bit"));
gen934.addSensor(new fb.SensorComparison("comparison"));



const gen934Body = (gen: fb.Generator) => {
    v8glue.UI_create_method(
	
	
	bh.ToString(gen.getField("arg0").value)
	
    );
};

export function F2905eaf84829553f109d69cd0e8e3cbb3db4a9ad () {
    body.Fuzzer("gen934", gen934, gen934Body, v8glue, rng);
}


// struct asn1_object_st *OBJ_nid2obj(int)

let gen935 = new fb.Generator("OBJ_nid2obj", rng);




gen935.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen935.addSensor(new fb.Sensor8BitCounter("8bit"));
gen935.addSensor(new fb.SensorComparison("comparison"));



const gen935Body = (gen: fb.Generator) => {
    v8glue.OBJ_nid2obj(
	
	
	gen.getField("arg0").value
	
    );
};

export function F9c15cea8f4734fadc396ec0b90726dea1f149644 () {
    body.Fuzzer("gen935", gen935, gen935Body, v8glue, rng);
}


// const char *SSL_alert_type_string_long(int)

let gen966 = new fb.Generator("SSL_alert_type_string_long", rng);




gen966.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen966.addSensor(new fb.Sensor8BitCounter("8bit"));
gen966.addSensor(new fb.SensorComparison("comparison"));



const gen966Body = (gen: fb.Generator) => {
    v8glue.SSL_alert_type_string_long(
	
	
	gen.getField("arg0").value
	
    );
};

export function Fa64c4183ebf34775e342b7db8f185e53224092c9 () {
    body.Fuzzer("gen966", gen966, gen966Body, v8glue, rng);
}


// void CRYPTO_set_mem_debug_options(long)

let gen978 = new fb.Generator("CRYPTO_set_mem_debug_options", rng);




gen978.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-9223372036854775809), BigInt(9223372036854775808)));








gen978.addSensor(new fb.Sensor8BitCounter("8bit"));
gen978.addSensor(new fb.SensorComparison("comparison"));



const gen978Body = (gen: fb.Generator) => {
    v8glue.CRYPTO_set_mem_debug_options(
	
	
	gen.getField("arg0").value
	
    );
};

export function F076dd4e443ac7604a639be4dcafce7ed8642edfc () {
    body.Fuzzer("gen978", gen978, gen978Body, v8glue, rng);
}


// int OBJ_sn2nid(const char *)

let gen979 = new fb.Generator("OBJ_sn2nid", rng);








gen979.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen979.addSensor(new fb.Sensor8BitCounter("8bit"));
gen979.addSensor(new fb.SensorComparison("comparison"));



const gen979Body = (gen: fb.Generator) => {
    v8glue.OBJ_sn2nid(
	
	
	bh.ToString(gen.getField("arg0").value)
	
    );
};

export function F04ca27d2727d2f59cac0bf37b440d9072fc6b7cc () {
    body.Fuzzer("gen979", gen979, gen979Body, v8glue, rng);
}


// int RAND_egd_bytes(const char *, int)

let gen988 = new fb.Generator("RAND_egd_bytes", rng);




gen988.addField(new fb.Integer("arg1", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));













gen988.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen988.addSensor(new fb.Sensor8BitCounter("8bit"));
gen988.addSensor(new fb.SensorComparison("comparison"));



const gen988Body = (gen: fb.Generator) => {
    v8glue.RAND_egd_bytes(
	
	
	bh.ToString(gen.getField("arg0").value)
	
	, 
	gen.getField("arg1").value
	
    );
};

export function Ff5bfae44e404ecab5babcaa9a9868dbf2843a5e3 () {
    body.Fuzzer("gen988", gen988, gen988Body, v8glue, rng);
}


// int BIO_sock_non_fatal_error(int)

let gen1015 = new fb.Generator("BIO_sock_non_fatal_error", rng);




gen1015.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen1015.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1015.addSensor(new fb.SensorComparison("comparison"));



const gen1015Body = (gen: fb.Generator) => {
    v8glue.BIO_sock_non_fatal_error(
	
	
	gen.getField("arg0").value
	
    );
};

export function F28e7ab0aff8acd1488479d8e3d3684a65f3a3e48 () {
    body.Fuzzer("gen1015", gen1015, gen1015Body, v8glue, rng);
}


// void OpenSSLDie(const char *, int, const char *)

let gen1021 = new fb.Generator("OpenSSLDie", rng);




gen1021.addField(new fb.Integer("arg1", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));













gen1021.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());









gen1021.addField(new fb.ByteArray("arg2", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen1021.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1021.addSensor(new fb.SensorComparison("comparison"));



const gen1021Body = (gen: fb.Generator) => {
    v8glue.OpenSSLDie(
	
	
	bh.ToString(gen.getField("arg0").value)
	
	, 
	gen.getField("arg1").value
	
	, 
	bh.ToString(gen.getField("arg2").value)
	
    );
};

export function F300d5d9f4acaa96a3e19b5c5b7cd0751217d8999 () {
    body.Fuzzer("gen1021", gen1021, gen1021Body, v8glue, rng);
}


// struct ec_key_st *EC_KEY_new_by_curve_name(int)

let gen1043 = new fb.Generator("EC_KEY_new_by_curve_name", rng);




gen1043.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen1043.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1043.addSensor(new fb.SensorComparison("comparison"));



const gen1043Body = (gen: fb.Generator) => {
    v8glue.EC_KEY_new_by_curve_name(
	
	
	gen.getField("arg0").value
	
    );
};

export function F6b51b926459b8d06ce56f207d0eac23f1cb48e3f () {
    body.Fuzzer("gen1043", gen1043, gen1043Body, v8glue, rng);
}


// struct ssl_method_st *ssl_bad_method(int)

let gen1062 = new fb.Generator("ssl_bad_method", rng);




gen1062.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen1062.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1062.addSensor(new fb.SensorComparison("comparison"));



const gen1062Body = (gen: fb.Generator) => {
    v8glue.ssl_bad_method(
	
	
	gen.getField("arg0").value
	
    );
};

export function F843a70847ed7f94a5050e239388247fe2f51a70e () {
    body.Fuzzer("gen1062", gen1062, gen1062Body, v8glue, rng);
}


// char *BUF_strdup(const char *)

let gen1079 = new fb.Generator("BUF_strdup", rng);








gen1079.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen1079.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1079.addSensor(new fb.SensorComparison("comparison"));



const gen1079Body = (gen: fb.Generator) => {
    v8glue.BUF_strdup(
	
	
	bh.ToString(gen.getField("arg0").value)
	
    );
};

export function Fb1bd9e6bb5c712af29fb86024e274d36728dde60 () {
    body.Fuzzer("gen1079", gen1079, gen1079Body, v8glue, rng);
}


// struct ec_group_st *EC_GROUP_new_by_curve_name(int)

let gen1087 = new fb.Generator("EC_GROUP_new_by_curve_name", rng);




gen1087.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen1087.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1087.addSensor(new fb.SensorComparison("comparison"));



const gen1087Body = (gen: fb.Generator) => {
    v8glue.EC_GROUP_new_by_curve_name(
	
	
	gen.getField("arg0").value
	
    );
};

export function Fa870d3ec6367b211d530e84081789035e48d9f53 () {
    body.Fuzzer("gen1087", gen1087, gen1087Body, v8glue, rng);
}


// const char *ERR_reason_error_string(unsigned long)

let gen1222 = new fb.Generator("ERR_reason_error_string", rng);




gen1222.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(0), BigInt("18446744073709551616")));








gen1222.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1222.addSensor(new fb.SensorComparison("comparison"));



const gen1222Body = (gen: fb.Generator) => {
    v8glue.ERR_reason_error_string(
	
	
	gen.getField("arg0").value
	
    );
};

export function Faeafccd98c1a29b1a43d7c8263d95a4c09b04bf6 () {
    body.Fuzzer("gen1222", gen1222, gen1222Body, v8glue, rng);
}


// const struct env_md_st *tls12_get_hash(unsigned char)

let gen1249 = new fb.Generator("tls12_get_hash", rng);




gen1249.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(0), BigInt(256)));








gen1249.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1249.addSensor(new fb.SensorComparison("comparison"));



const gen1249Body = (gen: fb.Generator) => {
    v8glue.tls12_get_hash(
	
	
	gen.getField("arg0").value
	
    );
};

export function Ffcb6e9345977648c45c5a9b507cd74bc77095caa () {
    body.Fuzzer("gen1249", gen1249, gen1249Body, v8glue, rng);
}


// int dtls1_get_queue_priority(unsigned short, int)

let gen1289 = new fb.Generator("dtls1_get_queue_priority", rng);




gen1289.addField(new fb.Integer("arg1", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));









gen1289.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(0), BigInt(65535)));








gen1289.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1289.addSensor(new fb.SensorComparison("comparison"));



const gen1289Body = (gen: fb.Generator) => {
    v8glue.dtls1_get_queue_priority(
	
	
	gen.getField("arg0").value
	
	, 
	gen.getField("arg1").value
	
    );
};

export function F9a51bb8b7186ea32ad6c2a1a2106107e4c355c0c () {
    body.Fuzzer("gen1289", gen1289, gen1289Body, v8glue, rng);
}


// struct CRYPTO_dynlock_value *CRYPTO_get_dynlock_value(int)

let gen1297 = new fb.Generator("CRYPTO_get_dynlock_value", rng);




gen1297.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen1297.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1297.addSensor(new fb.SensorComparison("comparison"));



const gen1297Body = (gen: fb.Generator) => {
    v8glue.CRYPTO_get_dynlock_value(
	
	
	gen.getField("arg0").value
	
    );
};

export function Fdd13e1e75414735910056181e4243b15290c2499 () {
    body.Fuzzer("gen1297", gen1297, gen1297Body, v8glue, rng);
}


// int tls1_alert_code(int)

let gen1325 = new fb.Generator("tls1_alert_code", rng);




gen1325.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen1325.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1325.addSensor(new fb.SensorComparison("comparison"));



const gen1325Body = (gen: fb.Generator) => {
    v8glue.tls1_alert_code(
	
	
	gen.getField("arg0").value
	
    );
};

export function F465d2b978111476900f8a0851870c20ed035a795 () {
    body.Fuzzer("gen1325", gen1325, gen1325Body, v8glue, rng);
}


// unsigned long BUF_strlcpy(char *, const char *, unsigned long)

let gen1330 = new fb.Generator("BUF_strlcpy", rng);



gen1330.addField(new fb.ByteArray("arg1", 4096, rng))
	.addDefaultMutators()








gen1330.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen1330.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1330.addSensor(new fb.SensorComparison("comparison"));



const gen1330Body = (gen: fb.Generator) => {
    v8glue.BUF_strlcpy(
	
	
	bh.ToString(gen.getField("arg0").value)
	
	, 
	gen.getField("arg1").value
	
	, 
	undefined
	
    );
};

export function F505571b978dcbfbec6f2cdaeccfec3ef04e1ed49 () {
    body.Fuzzer("gen1330", gen1330, gen1330Body, v8glue, rng);
}


// const struct X509_VERIFY_PARAM_st *X509_VERIFY_PARAM_lookup(const char *)

let gen1331 = new fb.Generator("X509_VERIFY_PARAM_lookup", rng);








gen1331.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen1331.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1331.addSensor(new fb.SensorComparison("comparison"));



const gen1331Body = (gen: fb.Generator) => {
    v8glue.X509_VERIFY_PARAM_lookup(
	
	
	bh.ToString(gen.getField("arg0").value)
	
    );
};

export function Fb818030be70dd7462e11aaf7abc7a28fe1962153 () {
    body.Fuzzer("gen1331", gen1331, gen1331Body, v8glue, rng);
}


// int X509_PURPOSE_get_by_id(int)

let gen1388 = new fb.Generator("X509_PURPOSE_get_by_id", rng);




gen1388.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen1388.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1388.addSensor(new fb.SensorComparison("comparison"));



const gen1388Body = (gen: fb.Generator) => {
    v8glue.X509_PURPOSE_get_by_id(
	
	
	gen.getField("arg0").value
	
    );
};

export function Fd063720e4cb29e6e6794c4d5d367c5bbaa9033d9 () {
    body.Fuzzer("gen1388", gen1388, gen1388Body, v8glue, rng);
}


// struct engine_st *ENGINE_get_digest_engine(int)

let gen1389 = new fb.Generator("ENGINE_get_digest_engine", rng);




gen1389.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen1389.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1389.addSensor(new fb.SensorComparison("comparison"));



const gen1389Body = (gen: fb.Generator) => {
    v8glue.ENGINE_get_digest_engine(
	
	
	gen.getField("arg0").value
	
    );
};

export function Fbdad082abdb69c313ff040a65e4cdb08e3107677 () {
    body.Fuzzer("gen1389", gen1389, gen1389Body, v8glue, rng);
}


// const struct v3_ext_method *X509V3_EXT_get_nid(int)

let gen1392 = new fb.Generator("X509V3_EXT_get_nid", rng);




gen1392.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen1392.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1392.addSensor(new fb.SensorComparison("comparison"));



const gen1392Body = (gen: fb.Generator) => {
    v8glue.X509V3_EXT_get_nid(
	
	
	gen.getField("arg0").value
	
    );
};

export function F4c5bbe1a85b8b8a9ba3fee167c5678edcc316ffd () {
    body.Fuzzer("gen1392", gen1392, gen1392Body, v8glue, rng);
}


// int CRYPTO_push_info_(const char *, const char *, int)

let gen1405 = new fb.Generator("CRYPTO_push_info_", rng);




gen1405.addField(new fb.Integer("arg2", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));













gen1405.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());









gen1405.addField(new fb.ByteArray("arg1", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen1405.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1405.addSensor(new fb.SensorComparison("comparison"));



const gen1405Body = (gen: fb.Generator) => {
    v8glue.CRYPTO_push_info_(
	
	
	bh.ToString(gen.getField("arg0").value)
	
	, 
	bh.ToString(gen.getField("arg1").value)
	
	, 
	gen.getField("arg2").value
	
    );
};

export function F6c398d138afb6fff67fa2c9182946d3383fb4866 () {
    body.Fuzzer("gen1405", gen1405, gen1405Body, v8glue, rng);
}


// void *DSO_global_lookup(const char *)

let gen1457 = new fb.Generator("DSO_global_lookup", rng);








gen1457.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen1457.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1457.addSensor(new fb.SensorComparison("comparison"));



const gen1457Body = (gen: fb.Generator) => {
    v8glue.DSO_global_lookup(
	
	
	bh.ToString(gen.getField("arg0").value)
	
    );
};

export function Fd2535c701d4e09f548989a3ef86a6c6f3c03604b () {
    body.Fuzzer("gen1457", gen1457, gen1457Body, v8glue, rng);
}


// struct SRP_gN_st *SRP_get_default_gN(const char *)

let gen1469 = new fb.Generator("SRP_get_default_gN", rng);








gen1469.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen1469.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1469.addSensor(new fb.SensorComparison("comparison"));



const gen1469Body = (gen: fb.Generator) => {
    v8glue.SRP_get_default_gN(
	
	
	bh.ToString(gen.getField("arg0").value)
	
    );
};

export function F608b32cfaab5c93dc4c7b4954dcc6e85029bd4cf () {
    body.Fuzzer("gen1469", gen1469, gen1469Body, v8glue, rng);
}


// struct engine_st *ENGINE_get_pkey_meth_engine(int)

let gen1566 = new fb.Generator("ENGINE_get_pkey_meth_engine", rng);




gen1566.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen1566.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1566.addSensor(new fb.SensorComparison("comparison"));



const gen1566Body = (gen: fb.Generator) => {
    v8glue.ENGINE_get_pkey_meth_engine(
	
	
	gen.getField("arg0").value
	
    );
};

export function Fa7fb86003a76e2553bbe57b40b699db72353a4e3 () {
    body.Fuzzer("gen1566", gen1566, gen1566Body, v8glue, rng);
}


// const char *CRYPTO_get_lock_name(int)

let gen1572 = new fb.Generator("CRYPTO_get_lock_name", rng);




gen1572.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen1572.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1572.addSensor(new fb.SensorComparison("comparison"));



const gen1572Body = (gen: fb.Generator) => {
    v8glue.CRYPTO_get_lock_name(
	
	
	gen.getField("arg0").value
	
    );
};

export function F22e38a1127e5dd20729c4c7385dd313a74875195 () {
    body.Fuzzer("gen1572", gen1572, gen1572Body, v8glue, rng);
}


// const char *SSL_alert_desc_string(int)

let gen1606 = new fb.Generator("SSL_alert_desc_string", rng);




gen1606.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen1606.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1606.addSensor(new fb.SensorComparison("comparison"));



const gen1606Body = (gen: fb.Generator) => {
    v8glue.SSL_alert_desc_string(
	
	
	gen.getField("arg0").value
	
    );
};

export function F378f1050c368e5bb809952a4babce43fa6ed3fa1 () {
    body.Fuzzer("gen1606", gen1606, gen1606Body, v8glue, rng);
}


// struct asn1_string_st *a2i_IPADDRESS(const char *)

let gen1644 = new fb.Generator("a2i_IPADDRESS", rng);








gen1644.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen1644.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1644.addSensor(new fb.SensorComparison("comparison"));



const gen1644Body = (gen: fb.Generator) => {
    v8glue.a2i_IPADDRESS(
	
	
	bh.ToString(gen.getField("arg0").value)
	
    );
};

export function Ff6c3c1e8c7585e606feaa1c1ebda69e590491bbd () {
    body.Fuzzer("gen1644", gen1644, gen1644Body, v8glue, rng);
}


// void EVP_set_pw_prompt(const char *)

let gen1652 = new fb.Generator("EVP_set_pw_prompt", rng);








gen1652.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen1652.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1652.addSensor(new fb.SensorComparison("comparison"));



const gen1652Body = (gen: fb.Generator) => {
    v8glue.EVP_set_pw_prompt(
	
	
	bh.ToString(gen.getField("arg0").value)
	
    );
};

export function F553e95e7d0d11368328c693892132ed32c6bde8e () {
    body.Fuzzer("gen1652", gen1652, gen1652Body, v8glue, rng);
}


// int rotate_serial(char *, char *, char *)

let gen1670 = new fb.Generator("rotate_serial", rng);








gen1670.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());









gen1670.addField(new fb.ByteArray("arg1", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());









gen1670.addField(new fb.ByteArray("arg2", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen1670.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1670.addSensor(new fb.SensorComparison("comparison"));



const gen1670Body = (gen: fb.Generator) => {
    v8glue.rotate_serial(
	
	
	bh.ToString(gen.getField("arg0").value)
	
	, 
	bh.ToString(gen.getField("arg1").value)
	
	, 
	bh.ToString(gen.getField("arg2").value)
	
    );
};

export function F3a6de72dc6a9231821fdd1857ef99fe8fc2479e5 () {
    body.Fuzzer("gen1670", gen1670, gen1670Body, v8glue, rng);
}


// int EVP_read_pw_string(char *, int, const char *, int)

let gen1692 = new fb.Generator("EVP_read_pw_string", rng);




gen1692.addField(new fb.Integer("arg1", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));









gen1692.addField(new fb.Integer("arg3", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));













gen1692.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());









gen1692.addField(new fb.ByteArray("arg2", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen1692.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1692.addSensor(new fb.SensorComparison("comparison"));



const gen1692Body = (gen: fb.Generator) => {
    v8glue.EVP_read_pw_string(
	
	
	bh.ToString(gen.getField("arg0").value)
	
	, 
	gen.getField("arg1").value
	
	, 
	bh.ToString(gen.getField("arg2").value)
	
	, 
	gen.getField("arg3").value
	
    );
};

export function Fd6d0e1643d32c580ed02aabfed4eea7a31259821 () {
    body.Fuzzer("gen1692", gen1692, gen1692Body, v8glue, rng);
}


// const struct env_md_st *EVP_get_digestbyname(const char *)

let gen1718 = new fb.Generator("EVP_get_digestbyname", rng);








gen1718.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen1718.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1718.addSensor(new fb.SensorComparison("comparison"));



const gen1718Body = (gen: fb.Generator) => {
    v8glue.EVP_get_digestbyname(
	
	
	bh.ToString(gen.getField("arg0").value)
	
    );
};

export function Ff13bbe52960485801a22bca127731aff6571ea00 () {
    body.Fuzzer("gen1718", gen1718, gen1718Body, v8glue, rng);
}


// int OBJ_new_nid(int)

let gen1726 = new fb.Generator("OBJ_new_nid", rng);




gen1726.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen1726.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1726.addSensor(new fb.SensorComparison("comparison"));



const gen1726Body = (gen: fb.Generator) => {
    v8glue.OBJ_new_nid(
	
	
	gen.getField("arg0").value
	
    );
};

export function F5b0f88f7b3515766bc77c5e2b3538917d3ae50ba () {
    body.Fuzzer("gen1726", gen1726, gen1726Body, v8glue, rng);
}


// int RAND_egd(const char *)

let gen1734 = new fb.Generator("RAND_egd", rng);








gen1734.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen1734.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1734.addSensor(new fb.SensorComparison("comparison"));



const gen1734Body = (gen: fb.Generator) => {
    v8glue.RAND_egd(
	
	
	bh.ToString(gen.getField("arg0").value)
	
    );
};

export function F7741397c54505522901b321d04a0f0181d96bd87 () {
    body.Fuzzer("gen1734", gen1734, gen1734Body, v8glue, rng);
}


// const char *ERR_func_error_string(unsigned long)

let gen1751 = new fb.Generator("ERR_func_error_string", rng);




gen1751.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(0), BigInt("18446744073709551616")));








gen1751.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1751.addSensor(new fb.SensorComparison("comparison"));



const gen1751Body = (gen: fb.Generator) => {
    v8glue.ERR_func_error_string(
	
	
	gen.getField("arg0").value
	
    );
};

export function Fb7fd0942506396403329e499416c8145d21fff8d () {
    body.Fuzzer("gen1751", gen1751, gen1751Body, v8glue, rng);
}


// const char *OBJ_nid2sn(int)

let gen1771 = new fb.Generator("OBJ_nid2sn", rng);




gen1771.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen1771.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1771.addSensor(new fb.SensorComparison("comparison"));



const gen1771Body = (gen: fb.Generator) => {
    v8glue.OBJ_nid2sn(
	
	
	gen.getField("arg0").value
	
    );
};

export function Fdbaa8d10bfcc89f27e7c15dc93e9b2cb148c8a9e () {
    body.Fuzzer("gen1771", gen1771, gen1771Body, v8glue, rng);
}


// void ERR_error_string_n(unsigned long, char *, unsigned long)

let gen1840 = new fb.Generator("ERR_error_string_n", rng);



gen1840.addField(new fb.ByteArray("arg1", 4096, rng))
	.addDefaultMutators()




gen1840.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(0), BigInt("18446744073709551616")));








gen1840.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1840.addSensor(new fb.SensorComparison("comparison"));



const gen1840Body = (gen: fb.Generator) => {
    v8glue.ERR_error_string_n(
	
	
	gen.getField("arg0").value
	
	, 
	gen.getField("arg1").value
	
	, 
	undefined
	
    );
};

export function Feb3e496e35232aeb5b7ead4d6e2fd112e0c8bcb0 () {
    body.Fuzzer("gen1840", gen1840, gen1840Body, v8glue, rng);
}


// struct asn1_string_st *a2i_IPADDRESS_NC(const char *)

let gen1849 = new fb.Generator("a2i_IPADDRESS_NC", rng);








gen1849.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen1849.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1849.addSensor(new fb.SensorComparison("comparison"));



const gen1849Body = (gen: fb.Generator) => {
    v8glue.a2i_IPADDRESS_NC(
	
	
	bh.ToString(gen.getField("arg0").value)
	
    );
};

export function F52b8b0b795b676bc9472876c6e75152d885aacdc () {
    body.Fuzzer("gen1849", gen1849, gen1849Body, v8glue, rng);
}


// void CRYPTO_dbg_set_options(long)

let gen1852 = new fb.Generator("CRYPTO_dbg_set_options", rng);




gen1852.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-9223372036854775809), BigInt(9223372036854775808)));








gen1852.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1852.addSensor(new fb.SensorComparison("comparison"));



const gen1852Body = (gen: fb.Generator) => {
    v8glue.CRYPTO_dbg_set_options(
	
	
	gen.getField("arg0").value
	
    );
};

export function F82335ac28b86f5ea26de5c171cdd936789beda08 () {
    body.Fuzzer("gen1852", gen1852, gen1852Body, v8glue, rng);
}


// int app_init(long)

let gen1861 = new fb.Generator("app_init", rng);




gen1861.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-9223372036854775809), BigInt(9223372036854775808)));








gen1861.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1861.addSensor(new fb.SensorComparison("comparison"));



const gen1861Body = (gen: fb.Generator) => {
    v8glue.app_init(
	
	
	gen.getField("arg0").value
	
    );
};

export function F6cef3c719d5773777c1f415016dcb77c817d8e08 () {
    body.Fuzzer("gen1861", gen1861, gen1861Body, v8glue, rng);
}


// unsigned long bn_div_words(unsigned long, unsigned long, unsigned long)

let gen1895 = new fb.Generator("bn_div_words", rng);




gen1895.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(0), BigInt("18446744073709551616")));









gen1895.addField(new fb.Integer("arg1", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(0), BigInt("18446744073709551616")));









gen1895.addField(new fb.Integer("arg2", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(0), BigInt("18446744073709551616")));








gen1895.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1895.addSensor(new fb.SensorComparison("comparison"));



const gen1895Body = (gen: fb.Generator) => {
    v8glue.bn_div_words(
	
	
	gen.getField("arg0").value
	
	, 
	gen.getField("arg1").value
	
	, 
	gen.getField("arg2").value
	
    );
};

export function F18ad0ab09eabd710082995c5427ba3efc36bc21a () {
    body.Fuzzer("gen1895", gen1895, gen1895Body, v8glue, rng);
}


// char *CRYPTO_strdup(const char *, const char *, int)

let gen1907 = new fb.Generator("CRYPTO_strdup", rng);




gen1907.addField(new fb.Integer("arg2", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));













gen1907.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());









gen1907.addField(new fb.ByteArray("arg1", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen1907.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1907.addSensor(new fb.SensorComparison("comparison"));



const gen1907Body = (gen: fb.Generator) => {
    v8glue.CRYPTO_strdup(
	
	
	bh.ToString(gen.getField("arg0").value)
	
	, 
	bh.ToString(gen.getField("arg1").value)
	
	, 
	gen.getField("arg2").value
	
    );
};

export function Fd6b01b638bdc9193db96414949f5a27d34b814c6 () {
    body.Fuzzer("gen1907", gen1907, gen1907Body, v8glue, rng);
}


// int EVP_PKEY_asn1_add_alias(int, int)

let gen1914 = new fb.Generator("EVP_PKEY_asn1_add_alias", rng);




gen1914.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));









gen1914.addField(new fb.Integer("arg1", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen1914.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1914.addSensor(new fb.SensorComparison("comparison"));



const gen1914Body = (gen: fb.Generator) => {
    v8glue.EVP_PKEY_asn1_add_alias(
	
	
	gen.getField("arg0").value
	
	, 
	gen.getField("arg1").value
	
    );
};

export function F1375428682ae931890b9506be00b036dd3cd6a9b () {
    body.Fuzzer("gen1914", gen1914, gen1914Body, v8glue, rng);
}


// void *CRYPTO_malloc_locked(int, const char *, int)

let gen1922 = new fb.Generator("CRYPTO_malloc_locked", rng);




gen1922.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));









gen1922.addField(new fb.Integer("arg2", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));













gen1922.addField(new fb.ByteArray("arg1", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen1922.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1922.addSensor(new fb.SensorComparison("comparison"));



const gen1922Body = (gen: fb.Generator) => {
    v8glue.CRYPTO_malloc_locked(
	
	
	gen.getField("arg0").value
	
	, 
	bh.ToString(gen.getField("arg1").value)
	
	, 
	gen.getField("arg2").value
	
    );
};

export function F35210f71d91dd9633ef15f6c0423b32acf77b808 () {
    body.Fuzzer("gen1922", gen1922, gen1922Body, v8glue, rng);
}


// int EVP_read_pw_string_min(char *, int, int, const char *, int)

let gen1925 = new fb.Generator("EVP_read_pw_string_min", rng);




gen1925.addField(new fb.Integer("arg1", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));









gen1925.addField(new fb.Integer("arg2", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));









gen1925.addField(new fb.Integer("arg4", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));













gen1925.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());









gen1925.addField(new fb.ByteArray("arg3", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen1925.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1925.addSensor(new fb.SensorComparison("comparison"));



const gen1925Body = (gen: fb.Generator) => {
    v8glue.EVP_read_pw_string_min(
	
	
	bh.ToString(gen.getField("arg0").value)
	
	, 
	gen.getField("arg1").value
	
	, 
	gen.getField("arg2").value
	
	, 
	bh.ToString(gen.getField("arg3").value)
	
	, 
	gen.getField("arg4").value
	
    );
};

export function F8af6f76675040e8c7615369e0de9e87c86429df5 () {
    body.Fuzzer("gen1925", gen1925, gen1925Body, v8glue, rng);
}


// int rotate_index(const char *, const char *, const char *)

let gen1939 = new fb.Generator("rotate_index", rng);








gen1939.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());









gen1939.addField(new fb.ByteArray("arg1", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());









gen1939.addField(new fb.ByteArray("arg2", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen1939.addSensor(new fb.Sensor8BitCounter("8bit"));
gen1939.addSensor(new fb.SensorComparison("comparison"));



const gen1939Body = (gen: fb.Generator) => {
    v8glue.rotate_index(
	
	
	bh.ToString(gen.getField("arg0").value)
	
	, 
	bh.ToString(gen.getField("arg1").value)
	
	, 
	bh.ToString(gen.getField("arg2").value)
	
    );
};

export function Ff75ea5a2a99da9e296edd68fb96d7c2ed5406f76 () {
    body.Fuzzer("gen1939", gen1939, gen1939Body, v8glue, rng);
}


// double app_tminterval(int, int)

let gen2035 = new fb.Generator("app_tminterval", rng);




gen2035.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));









gen2035.addField(new fb.Integer("arg1", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen2035.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2035.addSensor(new fb.SensorComparison("comparison"));



const gen2035Body = (gen: fb.Generator) => {
    v8glue.app_tminterval(
	
	
	gen.getField("arg0").value
	
	, 
	gen.getField("arg1").value
	
    );
};

export function F5b335a8cd08cdcf4ab52edac09273384629f1d81 () {
    body.Fuzzer("gen2035", gen2035, gen2035Body, v8glue, rng);
}


// void PEM_proc_type(char *, int)

let gen2057 = new fb.Generator("PEM_proc_type", rng);




gen2057.addField(new fb.Integer("arg1", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));













gen2057.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen2057.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2057.addSensor(new fb.SensorComparison("comparison"));



const gen2057Body = (gen: fb.Generator) => {
    v8glue.PEM_proc_type(
	
	
	bh.ToString(gen.getField("arg0").value)
	
	, 
	gen.getField("arg1").value
	
    );
};

export function F9ebf465984b4d3d462df0a85efc1d1a57dd366e1 () {
    body.Fuzzer("gen2057", gen2057, gen2057Body, v8glue, rng);
}


// void ENGINE_set_table_flags(unsigned int)

let gen2067 = new fb.Generator("ENGINE_set_table_flags", rng);




gen2067.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(0), BigInt(4294967296)));








gen2067.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2067.addSensor(new fb.SensorComparison("comparison"));



const gen2067Body = (gen: fb.Generator) => {
    v8glue.ENGINE_set_table_flags(
	
	
	gen.getField("arg0").value
	
    );
};

export function Ffc3eae03b7c6147bf704a41143b3201aac8e678b () {
    body.Fuzzer("gen2067", gen2067, gen2067Body, v8glue, rng);
}


// struct asn1_string_st *ASN1_STRING_type_new(int)

let gen2108 = new fb.Generator("ASN1_STRING_type_new", rng);




gen2108.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen2108.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2108.addSensor(new fb.SensorComparison("comparison"));



const gen2108Body = (gen: fb.Generator) => {
    v8glue.ASN1_STRING_type_new(
	
	
	gen.getField("arg0").value
	
    );
};

export function Fee3438b457610e881d1a76fabc55c781cb12f60a () {
    body.Fuzzer("gen2108", gen2108, gen2108Body, v8glue, rng);
}


// struct engine_st *ENGINE_get_cipher_engine(int)

let gen2136 = new fb.Generator("ENGINE_get_cipher_engine", rng);




gen2136.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen2136.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2136.addSensor(new fb.SensorComparison("comparison"));



const gen2136Body = (gen: fb.Generator) => {
    v8glue.ENGINE_get_cipher_engine(
	
	
	gen.getField("arg0").value
	
    );
};

export function Ff99cd567e7c2229386d56a60def3b18335e66f45 () {
    body.Fuzzer("gen2136", gen2136, gen2136Body, v8glue, rng);
}


// int X509_TRUST_get_by_id(int)

let gen2138 = new fb.Generator("X509_TRUST_get_by_id", rng);




gen2138.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen2138.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2138.addSensor(new fb.SensorComparison("comparison"));



const gen2138Body = (gen: fb.Generator) => {
    v8glue.X509_TRUST_get_by_id(
	
	
	gen.getField("arg0").value
	
    );
};

export function F1a0ad24f960f06ef6bb0504fedc40939c73b5924 () {
    body.Fuzzer("gen2138", gen2138, gen2138Body, v8glue, rng);
}


// int RSA_X931_hash_id(int)

let gen2145 = new fb.Generator("RSA_X931_hash_id", rng);




gen2145.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen2145.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2145.addSensor(new fb.SensorComparison("comparison"));



const gen2145Body = (gen: fb.Generator) => {
    v8glue.RSA_X931_hash_id(
	
	
	gen.getField("arg0").value
	
    );
};

export function Faa02fdc38bd323a2509f2aee2cd527139090d38b () {
    body.Fuzzer("gen2145", gen2145, gen2145Body, v8glue, rng);
}


// struct SRP_VBASE_st *SRP_VBASE_new(char *)

let gen2175 = new fb.Generator("SRP_VBASE_new", rng);








gen2175.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen2175.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2175.addSensor(new fb.SensorComparison("comparison"));



const gen2175Body = (gen: fb.Generator) => {
    v8glue.SRP_VBASE_new(
	
	
	bh.ToString(gen.getField("arg0").value)
	
    );
};

export function F4712dea9ac1fbf1aca226ba1ba0856973b00880b () {
    body.Fuzzer("gen2175", gen2175, gen2175Body, v8glue, rng);
}


// int OBJ_txt2nid(const char *)

let gen2203 = new fb.Generator("OBJ_txt2nid", rng);








gen2203.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen2203.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2203.addSensor(new fb.SensorComparison("comparison"));



const gen2203Body = (gen: fb.Generator) => {
    v8glue.OBJ_txt2nid(
	
	
	bh.ToString(gen.getField("arg0").value)
	
    );
};

export function F95518f2242375dacb0a81acf93538e2357043b1e () {
    body.Fuzzer("gen2203", gen2203, gen2203Body, v8glue, rng);
}


// int BIO_sock_should_retry(int)

let gen2240 = new fb.Generator("BIO_sock_should_retry", rng);




gen2240.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen2240.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2240.addSensor(new fb.SensorComparison("comparison"));



const gen2240Body = (gen: fb.Generator) => {
    v8glue.BIO_sock_should_retry(
	
	
	gen.getField("arg0").value
	
    );
};

export function Fbba77e6a898ffb5603d4cd5222a8baff6e48154c () {
    body.Fuzzer("gen2240", gen2240, gen2240Body, v8glue, rng);
}


// long app_RAND_load_files(char *)

let gen2260 = new fb.Generator("app_RAND_load_files", rng);








gen2260.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen2260.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2260.addSensor(new fb.SensorComparison("comparison"));



const gen2260Body = (gen: fb.Generator) => {
    v8glue.app_RAND_load_files(
	
	
	bh.ToString(gen.getField("arg0").value)
	
    );
};

export function Fb88a76850c4eca4c72763b708392a3e8912feb41 () {
    body.Fuzzer("gen2260", gen2260, gen2260Body, v8glue, rng);
}


// struct x509_purpose_st *X509_PURPOSE_get0(int)

let gen2344 = new fb.Generator("X509_PURPOSE_get0", rng);




gen2344.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen2344.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2344.addSensor(new fb.SensorComparison("comparison"));



const gen2344Body = (gen: fb.Generator) => {
    v8glue.X509_PURPOSE_get0(
	
	
	gen.getField("arg0").value
	
    );
};

export function F4e7b9aef1fb091f2fdba85081fe6d2f9641fb234 () {
    body.Fuzzer("gen2344", gen2344, gen2344Body, v8glue, rng);
}


// void CRYPTO_lock(int, int, const char *, int)

let gen2355 = new fb.Generator("CRYPTO_lock", rng);




gen2355.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));









gen2355.addField(new fb.Integer("arg1", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));









gen2355.addField(new fb.Integer("arg3", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));













gen2355.addField(new fb.ByteArray("arg2", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen2355.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2355.addSensor(new fb.SensorComparison("comparison"));



const gen2355Body = (gen: fb.Generator) => {
    v8glue.CRYPTO_lock(
	
	
	gen.getField("arg0").value
	
	, 
	gen.getField("arg1").value
	
	, 
	bh.ToString(gen.getField("arg2").value)
	
	, 
	gen.getField("arg3").value
	
    );
};

export function F16f7edcd1a50c072c57dfb946cfd71b01b6135b5 () {
    body.Fuzzer("gen2355", gen2355, gen2355Body, v8glue, rng);
}


// struct engine_st *ENGINE_get_pkey_asn1_meth_engine(int)

let gen2404 = new fb.Generator("ENGINE_get_pkey_asn1_meth_engine", rng);




gen2404.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen2404.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2404.addSensor(new fb.SensorComparison("comparison"));



const gen2404Body = (gen: fb.Generator) => {
    v8glue.ENGINE_get_pkey_asn1_meth_engine(
	
	
	gen.getField("arg0").value
	
    );
};

export function Fa76e0fccaf363a0e1497edba0fb8dc01118d5679 () {
    body.Fuzzer("gen2404", gen2404, gen2404Body, v8glue, rng);
}


// int X509_REQ_extension_nid(int)

let gen2425 = new fb.Generator("X509_REQ_extension_nid", rng);




gen2425.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen2425.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2425.addSensor(new fb.SensorComparison("comparison"));



const gen2425Body = (gen: fb.Generator) => {
    v8glue.X509_REQ_extension_nid(
	
	
	gen.getField("arg0").value
	
    );
};

export function Fbaa47876d40e51082bc810e6fd6d1762a5bb1e67 () {
    body.Fuzzer("gen2425", gen2425, gen2425Body, v8glue, rng);
}


// int ASN1_STRING_TABLE_add(int, long, long, unsigned long, unsigned long)

let gen2481 = new fb.Generator("ASN1_STRING_TABLE_add", rng);




gen2481.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));









gen2481.addField(new fb.Integer("arg1", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-9223372036854775809), BigInt(9223372036854775808)));









gen2481.addField(new fb.Integer("arg2", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-9223372036854775809), BigInt(9223372036854775808)));









gen2481.addField(new fb.Integer("arg3", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(0), BigInt("18446744073709551616")));









gen2481.addField(new fb.Integer("arg4", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(0), BigInt("18446744073709551616")));








gen2481.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2481.addSensor(new fb.SensorComparison("comparison"));



const gen2481Body = (gen: fb.Generator) => {
    v8glue.ASN1_STRING_TABLE_add(
	
	
	gen.getField("arg0").value
	
	, 
	gen.getField("arg1").value
	
	, 
	gen.getField("arg2").value
	
	, 
	gen.getField("arg3").value
	
	, 
	gen.getField("arg4").value
	
    );
};

export function F038b95ea39c67b844ab65dc0a780f70cae7e6c2a () {
    body.Fuzzer("gen2481", gen2481, gen2481Body, v8glue, rng);
}


// const char *ERR_lib_error_string(unsigned long)

let gen2486 = new fb.Generator("ERR_lib_error_string", rng);




gen2486.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(0), BigInt("18446744073709551616")));








gen2486.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2486.addSensor(new fb.SensorComparison("comparison"));



const gen2486Body = (gen: fb.Generator) => {
    v8glue.ERR_lib_error_string(
	
	
	gen.getField("arg0").value
	
    );
};

export function F7b8024edd2cb6c3f1cc8078f7ef45be917f629cb () {
    body.Fuzzer("gen2486", gen2486, gen2486Body, v8glue, rng);
}


// int OBJ_add_sigid(int, int, int)

let gen2509 = new fb.Generator("OBJ_add_sigid", rng);




gen2509.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));









gen2509.addField(new fb.Integer("arg1", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));









gen2509.addField(new fb.Integer("arg2", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen2509.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2509.addSensor(new fb.SensorComparison("comparison"));



const gen2509Body = (gen: fb.Generator) => {
    v8glue.OBJ_add_sigid(
	
	
	gen.getField("arg0").value
	
	, 
	gen.getField("arg1").value
	
	, 
	gen.getField("arg2").value
	
    );
};

export function F4d4414daaba1955bbf79d269e1b7ba839cdc9ca4 () {
    body.Fuzzer("gen2509", gen2509, gen2509Body, v8glue, rng);
}


// void CONF_modules_unload(int)

let gen2511 = new fb.Generator("CONF_modules_unload", rng);




gen2511.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen2511.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2511.addSensor(new fb.SensorComparison("comparison"));



const gen2511Body = (gen: fb.Generator) => {
    v8glue.CONF_modules_unload(
	
	
	gen.getField("arg0").value
	
    );
};

export function Ff6d2c477c7f13e1e899f957615eb749dbd57b8d6 () {
    body.Fuzzer("gen2511", gen2511, gen2511Body, v8glue, rng);
}


// int ASN1_object_size(int, int, int)

let gen2515 = new fb.Generator("ASN1_object_size", rng);




gen2515.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));









gen2515.addField(new fb.Integer("arg1", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));









gen2515.addField(new fb.Integer("arg2", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen2515.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2515.addSensor(new fb.SensorComparison("comparison"));



const gen2515Body = (gen: fb.Generator) => {
    v8glue.ASN1_object_size(
	
	
	gen.getField("arg0").value
	
	, 
	gen.getField("arg1").value
	
	, 
	gen.getField("arg2").value
	
    );
};

export function F8d6a9fe332e35d8a57ac25a353245f25c512003e () {
    body.Fuzzer("gen2515", gen2515, gen2515Body, v8glue, rng);
}


// struct X509_name_st *parse_name(char *, long, int)

let gen2518 = new fb.Generator("parse_name", rng);




gen2518.addField(new fb.Integer("arg2", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));









gen2518.addField(new fb.Integer("arg1", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-9223372036854775809), BigInt(9223372036854775808)));













gen2518.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen2518.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2518.addSensor(new fb.SensorComparison("comparison"));



const gen2518Body = (gen: fb.Generator) => {
    v8glue.parse_name(
	
	
	bh.ToString(gen.getField("arg0").value)
	
	, 
	gen.getField("arg1").value
	
	, 
	gen.getField("arg2").value
	
    );
};

export function F4329736e1589184872835a4f98db8eb5af70fbf7 () {
    body.Fuzzer("gen2518", gen2518, gen2518Body, v8glue, rng);
}


// void PEM_dek_info(char *, const char *, int, char *)

let gen2559 = new fb.Generator("PEM_dek_info", rng);




gen2559.addField(new fb.Integer("arg2", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));













gen2559.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());









gen2559.addField(new fb.ByteArray("arg1", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());









gen2559.addField(new fb.ByteArray("arg3", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen2559.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2559.addSensor(new fb.SensorComparison("comparison"));



const gen2559Body = (gen: fb.Generator) => {
    v8glue.PEM_dek_info(
	
	
	bh.ToString(gen.getField("arg0").value)
	
	, 
	bh.ToString(gen.getField("arg1").value)
	
	, 
	gen.getField("arg2").value
	
	, 
	bh.ToString(gen.getField("arg3").value)
	
    );
};

export function F37a306f689a08e7c2e1e17eab539f5be6e77b66e () {
    body.Fuzzer("gen2559", gen2559, gen2559Body, v8glue, rng);
}


// void ASN1_STRING_set_default_mask(unsigned long)

let gen2562 = new fb.Generator("ASN1_STRING_set_default_mask", rng);




gen2562.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(0), BigInt("18446744073709551616")));








gen2562.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2562.addSensor(new fb.SensorComparison("comparison"));



const gen2562Body = (gen: fb.Generator) => {
    v8glue.ASN1_STRING_set_default_mask(
	
	
	gen.getField("arg0").value
	
    );
};

export function Fc036a5579c62496353b3324cb8602a237939e243 () {
    body.Fuzzer("gen2562", gen2562, gen2562Body, v8glue, rng);
}


// int name_cmp(const char *, const char *)

let gen2572 = new fb.Generator("name_cmp", rng);








gen2572.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());









gen2572.addField(new fb.ByteArray("arg1", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen2572.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2572.addSensor(new fb.SensorComparison("comparison"));



const gen2572Body = (gen: fb.Generator) => {
    v8glue.name_cmp(
	
	
	bh.ToString(gen.getField("arg0").value)
	
	, 
	bh.ToString(gen.getField("arg1").value)
	
    );
};

export function F9b78f1f5586a6d31329c27fc8c37cbba8cea1970 () {
    body.Fuzzer("gen2572", gen2572, gen2572Body, v8glue, rng);
}


// const char *OBJ_NAME_get(const char *, int)

let gen2591 = new fb.Generator("OBJ_NAME_get", rng);




gen2591.addField(new fb.Integer("arg1", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));













gen2591.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen2591.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2591.addSensor(new fb.SensorComparison("comparison"));



const gen2591Body = (gen: fb.Generator) => {
    v8glue.OBJ_NAME_get(
	
	
	bh.ToString(gen.getField("arg0").value)
	
	, 
	gen.getField("arg1").value
	
    );
};

export function F0ee2a72b66ef5ee7d90c8adbaa3d80ecaff3c6db () {
    body.Fuzzer("gen2591", gen2591, gen2591Body, v8glue, rng);
}


// void BN_set_params(int, int, int, int)

let gen2596 = new fb.Generator("BN_set_params", rng);




gen2596.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));









gen2596.addField(new fb.Integer("arg1", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));









gen2596.addField(new fb.Integer("arg2", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));









gen2596.addField(new fb.Integer("arg3", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen2596.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2596.addSensor(new fb.SensorComparison("comparison"));



const gen2596Body = (gen: fb.Generator) => {
    v8glue.BN_set_params(
	
	
	gen.getField("arg0").value
	
	, 
	gen.getField("arg1").value
	
	, 
	gen.getField("arg2").value
	
	, 
	gen.getField("arg3").value
	
    );
};

export function F041b27d285caa212cbb08c4035c69451a07ef25f () {
    body.Fuzzer("gen2596", gen2596, gen2596Body, v8glue, rng);
}


// unsigned long ASN1_tag2bit(int)

let gen2677 = new fb.Generator("ASN1_tag2bit", rng);




gen2677.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen2677.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2677.addSensor(new fb.SensorComparison("comparison"));



const gen2677Body = (gen: fb.Generator) => {
    v8glue.ASN1_tag2bit(
	
	
	gen.getField("arg0").value
	
    );
};

export function F9317c7310716ce636e0ea3c84e4161f09b046621 () {
    body.Fuzzer("gen2677", gen2677, gen2677Body, v8glue, rng);
}


// const struct ssl_cipher_st *ssl23_get_cipher(unsigned int)

let gen2689 = new fb.Generator("ssl23_get_cipher", rng);




gen2689.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(0), BigInt(4294967296)));








gen2689.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2689.addSensor(new fb.SensorComparison("comparison"));



const gen2689Body = (gen: fb.Generator) => {
    v8glue.ssl23_get_cipher(
	
	
	gen.getField("arg0").value
	
    );
};

export function F7f9cfc39e7a1e02a02d3d84aa3e661496aa80224 () {
    body.Fuzzer("gen2689", gen2689, gen2689Body, v8glue, rng);
}


// int tls1_ec_nid2curve_id(int)

let gen2735 = new fb.Generator("tls1_ec_nid2curve_id", rng);




gen2735.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen2735.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2735.addSensor(new fb.SensorComparison("comparison"));



const gen2735Body = (gen: fb.Generator) => {
    v8glue.tls1_ec_nid2curve_id(
	
	
	gen.getField("arg0").value
	
    );
};

export function F8ac4c09b073ffc7e7aee718460a3aa90ad6c1ad4 () {
    body.Fuzzer("gen2735", gen2735, gen2735Body, v8glue, rng);
}


// const char *SSL_alert_type_string(int)

let gen2741 = new fb.Generator("SSL_alert_type_string", rng);




gen2741.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen2741.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2741.addSensor(new fb.SensorComparison("comparison"));



const gen2741Body = (gen: fb.Generator) => {
    v8glue.SSL_alert_type_string(
	
	
	gen.getField("arg0").value
	
    );
};

export function Fd2b196423662824548125de52937919264c5a553 () {
    body.Fuzzer("gen2741", gen2741, gen2741Body, v8glue, rng);
}


// char *BUF_strndup(const char *, unsigned long)

let gen2784 = new fb.Generator("BUF_strndup", rng);



gen2784.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()



gen2784.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2784.addSensor(new fb.SensorComparison("comparison"));



const gen2784Body = (gen: fb.Generator) => {
    v8glue.BUF_strndup(
	
	
	gen.getField("arg0").value
	
	, 
	undefined
	
    );
};

export function F08e08b0ce3ff218c6ea2ff98d7de97554a0582b3 () {
    body.Fuzzer("gen2784", gen2784, gen2784Body, v8glue, rng);
}


// struct stack_st_CONF_VALUE *X509V3_parse_list(const char *)

let gen2788 = new fb.Generator("X509V3_parse_list", rng);








gen2788.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen2788.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2788.addSensor(new fb.SensorComparison("comparison"));



const gen2788Body = (gen: fb.Generator) => {
    v8glue.X509V3_parse_list(
	
	
	bh.ToString(gen.getField("arg0").value)
	
    );
};

export function F4d10e764b76687a6c390fc019a1bec479ca241c1 () {
    body.Fuzzer("gen2788", gen2788, gen2788Body, v8glue, rng);
}


// struct asn1_object_st *OBJ_txt2obj(const char *, int)

let gen2796 = new fb.Generator("OBJ_txt2obj", rng);




gen2796.addField(new fb.Integer("arg1", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));













gen2796.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen2796.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2796.addSensor(new fb.SensorComparison("comparison"));



const gen2796Body = (gen: fb.Generator) => {
    v8glue.OBJ_txt2obj(
	
	
	bh.ToString(gen.getField("arg0").value)
	
	, 
	gen.getField("arg1").value
	
    );
};

export function F9261d350d6293b95eff793a0e4b54077167908df () {
    body.Fuzzer("gen2796", gen2796, gen2796Body, v8glue, rng);
}


// int tls1_ec_curve_id2nid(int)

let gen2804 = new fb.Generator("tls1_ec_curve_id2nid", rng);




gen2804.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen2804.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2804.addSensor(new fb.SensorComparison("comparison"));



const gen2804Body = (gen: fb.Generator) => {
    v8glue.tls1_ec_curve_id2nid(
	
	
	gen.getField("arg0").value
	
    );
};

export function F3ffbd77e38b703ce0b310326a92bcfc6fad31ea2 () {
    body.Fuzzer("gen2804", gen2804, gen2804Body, v8glue, rng);
}


// const char *SSL_alert_desc_string_long(int)

let gen2811 = new fb.Generator("SSL_alert_desc_string_long", rng);




gen2811.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen2811.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2811.addSensor(new fb.SensorComparison("comparison"));



const gen2811Body = (gen: fb.Generator) => {
    v8glue.SSL_alert_desc_string_long(
	
	
	gen.getField("arg0").value
	
    );
};

export function F067a0c4bb134af4744afce63433406e7c80394c2 () {
    body.Fuzzer("gen2811", gen2811, gen2811Body, v8glue, rng);
}


// int OBJ_create(const char *, const char *, const char *)

let gen2855 = new fb.Generator("OBJ_create", rng);








gen2855.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());









gen2855.addField(new fb.ByteArray("arg1", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());









gen2855.addField(new fb.ByteArray("arg2", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen2855.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2855.addSensor(new fb.SensorComparison("comparison"));



const gen2855Body = (gen: fb.Generator) => {
    v8glue.OBJ_create(
	
	
	bh.ToString(gen.getField("arg0").value)
	
	, 
	bh.ToString(gen.getField("arg1").value)
	
	, 
	bh.ToString(gen.getField("arg2").value)
	
    );
};

export function F178c7c8f9a31ec105b74563bf462289171172284 () {
    body.Fuzzer("gen2855", gen2855, gen2855Body, v8glue, rng);
}


// void program_name(char *, char *, int)

let gen2874 = new fb.Generator("program_name", rng);




gen2874.addField(new fb.Integer("arg2", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));













gen2874.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());









gen2874.addField(new fb.ByteArray("arg1", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen2874.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2874.addSensor(new fb.SensorComparison("comparison"));



const gen2874Body = (gen: fb.Generator) => {
    v8glue.program_name(
	
	
	bh.ToString(gen.getField("arg0").value)
	
	, 
	bh.ToString(gen.getField("arg1").value)
	
	, 
	gen.getField("arg2").value
	
    );
};

export function F0acd9799353eb07afc0dd218536343cd3434980c () {
    body.Fuzzer("gen2874", gen2874, gen2874Body, v8glue, rng);
}


// int FuzzerEntrypoint(const unsigned char *, unsigned long)

let gen2881 = new fb.Generator("FuzzerEntrypoint", rng);



gen2881.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()



gen2881.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2881.addSensor(new fb.SensorComparison("comparison"));



const gen2881Body = (gen: fb.Generator) => {
    v8glue.FuzzerEntrypoint(
	
	
	gen.getField("arg0").value
	
	, 
	undefined
	
    );
};

export function F7edcf1f0d8c089d919e1bcd8c0f8603303446385 () {
    body.Fuzzer("gen2881", gen2881, gen2881Body, v8glue, rng);
}


// int ASN1_STRING_set_default_mask_asc(const char *)

let gen2889 = new fb.Generator("ASN1_STRING_set_default_mask_asc", rng);








gen2889.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen2889.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2889.addSensor(new fb.SensorComparison("comparison"));



const gen2889Body = (gen: fb.Generator) => {
    v8glue.ASN1_STRING_set_default_mask_asc(
	
	
	bh.ToString(gen.getField("arg0").value)
	
    );
};

export function Ffd174d30c2aedff651e9d313705f98d503d5c5d0 () {
    body.Fuzzer("gen2889", gen2889, gen2889Body, v8glue, rng);
}


// void ERR_put_error(int, int, int, const char *, int)

let gen2901 = new fb.Generator("ERR_put_error", rng);




gen2901.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));









gen2901.addField(new fb.Integer("arg1", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));









gen2901.addField(new fb.Integer("arg2", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));









gen2901.addField(new fb.Integer("arg4", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));













gen2901.addField(new fb.ByteArray("arg3", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen2901.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2901.addSensor(new fb.SensorComparison("comparison"));



const gen2901Body = (gen: fb.Generator) => {
    v8glue.ERR_put_error(
	
	
	gen.getField("arg0").value
	
	, 
	gen.getField("arg1").value
	
	, 
	gen.getField("arg2").value
	
	, 
	bh.ToString(gen.getField("arg3").value)
	
	, 
	gen.getField("arg4").value
	
    );
};

export function Fa6dd7e91f8d016443706dd74439d19194164225f () {
    body.Fuzzer("gen2901", gen2901, gen2901Body, v8glue, rng);
}


// int OBJ_ln2nid(const char *)

let gen2933 = new fb.Generator("OBJ_ln2nid", rng);








gen2933.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen2933.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2933.addSensor(new fb.SensorComparison("comparison"));



const gen2933Body = (gen: fb.Generator) => {
    v8glue.OBJ_ln2nid(
	
	
	bh.ToString(gen.getField("arg0").value)
	
    );
};

export function F0bd060e375f198fcd8462888f79e6edf7387a4c5 () {
    body.Fuzzer("gen2933", gen2933, gen2933Body, v8glue, rng);
}


// int ssl_verify_alarm_type(long)

let gen2949 = new fb.Generator("ssl_verify_alarm_type", rng);




gen2949.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-9223372036854775809), BigInt(9223372036854775808)));








gen2949.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2949.addSensor(new fb.SensorComparison("comparison"));



const gen2949Body = (gen: fb.Generator) => {
    v8glue.ssl_verify_alarm_type(
	
	
	gen.getField("arg0").value
	
    );
};

export function Fccbaf4004fbbf38aeb34e3681f34a6688e047716 () {
    body.Fuzzer("gen2949", gen2949, gen2949Body, v8glue, rng);
}


// int CRYPTO_mem_ctrl(int)

let gen2964 = new fb.Generator("CRYPTO_mem_ctrl", rng);




gen2964.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen2964.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2964.addSensor(new fb.SensorComparison("comparison"));



const gen2964Body = (gen: fb.Generator) => {
    v8glue.CRYPTO_mem_ctrl(
	
	
	gen.getField("arg0").value
	
    );
};

export function F3535a390f029534b7299ab3d55ef37fb80ed7c5c () {
    body.Fuzzer("gen2964", gen2964, gen2964Body, v8glue, rng);
}


// const struct evp_cipher_st *EVP_get_cipherbyname(const char *)

let gen2983 = new fb.Generator("EVP_get_cipherbyname", rng);








gen2983.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen2983.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2983.addSensor(new fb.SensorComparison("comparison"));



const gen2983Body = (gen: fb.Generator) => {
    v8glue.EVP_get_cipherbyname(
	
	
	bh.ToString(gen.getField("arg0").value)
	
    );
};

export function F2419add76f8cd55715547acc4402a815fa0eeb4a () {
    body.Fuzzer("gen2983", gen2983, gen2983Body, v8glue, rng);
}


// const char *OBJ_nid2ln(int)

let gen2999 = new fb.Generator("OBJ_nid2ln", rng);




gen2999.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen2999.addSensor(new fb.Sensor8BitCounter("8bit"));
gen2999.addSensor(new fb.SensorComparison("comparison"));



const gen2999Body = (gen: fb.Generator) => {
    v8glue.OBJ_nid2ln(
	
	
	gen.getField("arg0").value
	
    );
};

export function F6547564823d8009aca81830335e18b7737d66dca () {
    body.Fuzzer("gen2999", gen2999, gen2999Body, v8glue, rng);
}


// struct bio_st *BIO_new_socket(int, int)

let gen3000 = new fb.Generator("BIO_new_socket", rng);




gen3000.addField(new fb.Integer("arg0", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));









gen3000.addField(new fb.Integer("arg1", rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNumberRange(BigInt(-2147483649), BigInt(2147483648)));








gen3000.addSensor(new fb.Sensor8BitCounter("8bit"));
gen3000.addSensor(new fb.SensorComparison("comparison"));



const gen3000Body = (gen: fb.Generator) => {
    v8glue.BIO_new_socket(
	
	
	gen.getField("arg0").value
	
	, 
	gen.getField("arg1").value
	
    );
};

export function F2562d216df5ea9122a08251a0b1087b472bfdec8 () {
    body.Fuzzer("gen3000", gen3000, gen3000Body, v8glue, rng);
}


// struct engine_st *ENGINE_by_id(const char *)

let gen3004 = new fb.Generator("ENGINE_by_id", rng);








gen3004.addField(new fb.ByteArray("arg0", 4096, rng))
	.addDefaultMutators()
	.addConstraint(new fb.ConstraintNoNullBytes());




gen3004.addSensor(new fb.Sensor8BitCounter("8bit"));
gen3004.addSensor(new fb.SensorComparison("comparison"));



const gen3004Body = (gen: fb.Generator) => {
    v8glue.ENGINE_by_id(
	
	
	bh.ToString(gen.getField("arg0").value)
	
    );
};

export function F9bdd83dd17fa8f01e7fe2753a8f0b0cd945805ef () {
    body.Fuzzer("gen3004", gen3004, gen3004Body, v8glue, rng);
}


