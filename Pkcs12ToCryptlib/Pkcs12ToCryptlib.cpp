// Pkcs12ToCryptlib.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <cryptlib.h>

#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include <vector>


void check(const int n, const CRYPT_HANDLE c, char *s)
{
	auto locus = 0;
	auto type = 0;
	auto length = 0;

	if (n == CRYPT_OK)
		return;

	cryptGetAttribute(c, CRYPT_ATTRIBUTE_ERRORLOCUS, &locus);
	cryptGetAttribute(c, CRYPT_ATTRIBUTE_ERRORTYPE, &type);

	fprintf(stderr, "%s failed.\n", s);
	fprintf(stderr, "\tError code: %d\n", n);
	if (locus != 0) fprintf(stderr, "\tError locus: %d\n", locus);
	if (type != 0) fprintf(stderr, "\tError type: %d\n", type);

	auto status = cryptGetAttributeString(c, CRYPT_ATTRIBUTE_ERRORMESSAGE, nullptr, &length);
	if (cryptStatusOK(status))
	{
		const auto err = static_cast<char *>(malloc(length));
		if (!err) exit(-1);
		status = cryptGetAttributeString(c, CRYPT_ATTRIBUTE_ERRORMESSAGE, err, &length);
		if (cryptStatusOK(status))
			fprintf(stderr, "\tError message: %s\n", err);
	}

	exit(-1);
}

int main(int argc, char *argv[])
{
	if (argc != 6)
	{
		fprintf(stderr, "Syntax: %s <p12 filename> <p12 passwd> <out p15 filename> <label> <passwd>\n", argv[0]);
		exit(-1);
	}

	auto p12_filename = argv[1];
	auto p12_passwd = argv[2];
	auto out_p15_filename = argv[3];
	auto label = argv[4];
	auto passwd = argv[5];

	FILE *in = nullptr;
	fopen_s(&in, p12_filename, "rb");
	if (in == nullptr)
	{
		fprintf(stderr, "Could not open file: '%s'.\n", p12_filename);
		exit(-1);
	}

	auto p12_struct = d2i_PKCS12_fp(in, nullptr);
	fclose(in);

	OpenSSL_add_all_algorithms();

	auto res = PKCS12_verify_mac(p12_struct, p12_passwd, strlen(p12_passwd));
	if (res == 0)
	{
		fprintf(stderr, "File '%s' is corrupted, MAC is not correct?\n", p12_filename);
		ERR_print_errors_fp(stderr);
		exit(-1);
	}

	EVP_PKEY *private_key = nullptr;
	X509 *x509_cert = nullptr;
	STACK_OF(X509) *additional_certs = nullptr;
	res = PKCS12_parse(p12_struct, p12_passwd, &private_key, &x509_cert, &additional_certs);
	if (res == 0)
	{
		fprintf(stderr, "Could not parse file: '%s'.\n", p12_filename);
		ERR_print_errors_fp(stderr);
		exit(-1);
	}

	unsigned char * certStruct = nullptr;
	auto certStructLen = i2d_X509(x509_cert, &certStruct);
	if (certStructLen < 0)
	{
		fprintf(stderr, "Could not find certificate in '%s'.\n", p12_filename);
		ERR_print_errors_fp(stderr);
		exit(-1);
	}

	RSA *rsaKey = EVP_PKEY_get1_RSA(private_key);
	if (rsaKey == nullptr)
	{
		fprintf(stderr, "Could not find private key in '%s'?\n", p12_filename);
		ERR_print_errors_fp(stderr);
		exit(-1);
	}

	auto status = cryptInit();
	if (status != CRYPT_OK)
	{
		fprintf(stderr, "cryptInit failed!\n");
		exit(-1);
	}

	CRYPT_PKCINFO_RSA rsa;
	{
		cryptInitComponents(&rsa, CRYPT_KEYTYPE_PRIVATE);

		// modulus
		std::vector<unsigned char> n(BN_num_bytes(rsaKey->n));
		BN_bn2bin(rsaKey->n, &n[0]);

		// exponents
		std::vector<unsigned char> e(BN_num_bytes(rsaKey->e));
		std::vector<unsigned char> d(BN_num_bytes(rsaKey->d));
		BN_bn2bin(rsaKey->e, &e[0]);
		BN_bn2bin(rsaKey->d, &d[0]);

		// prime numbers
		std::vector<unsigned char> p(BN_num_bytes(rsaKey->p));
		std::vector<unsigned char> q(BN_num_bytes(rsaKey->q));
		BN_bn2bin(rsaKey->p, &p[0]);
		BN_bn2bin(rsaKey->q, &q[0]);

		// chinese remainders
		std::vector<unsigned char> iqmp(BN_num_bytes(rsaKey->iqmp));
		std::vector<unsigned char> dmp1(BN_num_bytes(rsaKey->dmp1));
		std::vector<unsigned char> dmq1(BN_num_bytes(rsaKey->dmq1));
		BN_bn2bin(rsaKey->iqmp, &iqmp[0]);
		BN_bn2bin(rsaKey->dmp1, &dmp1[0]);
		BN_bn2bin(rsaKey->dmq1, &dmq1[0]);

		cryptSetComponent((&rsa)->n, &n[0], BN_num_bits(rsaKey->n));
		cryptSetComponent((&rsa)->e, &e[0], BN_num_bits(rsaKey->e));
		cryptSetComponent((&rsa)->d, &d[0], BN_num_bits(rsaKey->d));
		cryptSetComponent((&rsa)->p, &p[0], BN_num_bits(rsaKey->p));
		cryptSetComponent((&rsa)->q, &q[0], BN_num_bits(rsaKey->q));
		cryptSetComponent((&rsa)->u, &iqmp[0], BN_num_bits(rsaKey->iqmp));
		cryptSetComponent((&rsa)->e1, &dmp1[0], BN_num_bits(rsaKey->dmp1));
		cryptSetComponent((&rsa)->e2, &dmq1[0], BN_num_bits(rsaKey->dmq1));
	}

	CRYPT_CONTEXT pKey;
	auto r = cryptCreateContext(&pKey, CRYPT_UNUSED, CRYPT_ALGO_RSA);
	check(r, pKey, "cryptCreateContext");

	r = cryptSetAttributeString(pKey, CRYPT_CTXINFO_LABEL, label, strlen(label));
	check(r, pKey, "cryptSetAttributeString(LABEL)");

	r = cryptSetAttributeString(pKey, CRYPT_CTXINFO_KEY_COMPONENTS, &rsa, sizeof(CRYPT_PKCINFO_RSA));
	check(r, pKey, "cryptSetAttributeString(KEY_COMPONENTS)");

	CRYPT_CERTIFICATE cert;
	r = cryptImportCert(certStruct, certStructLen, CRYPT_UNUSED, &cert);
	check(r, cert, "cryptImportCert");

	int usage;
	r = cryptGetAttribute(cert, CRYPT_CERTINFO_KEYUSAGE, &usage);
	if (r != CRYPT_OK)
	{
		fprintf(stderr, "Warning: The certificate specifies no KEYUSAGE.\n");
	}

	CRYPT_KEYSET key_set;
	r = cryptKeysetOpen(&key_set, CRYPT_UNUSED, CRYPT_KEYSET_FILE, out_p15_filename, CRYPT_KEYOPT_CREATE);
	check(r, key_set, "cryptKeysetOpen");

	r = cryptAddPrivateKey(key_set, pKey, passwd);
	check(r, key_set, "cryptAddPrivateKey");
	r = cryptAddPublicKey(key_set, cert);
	check(r, key_set, "cryptAddPublicKey");

	cryptDestroyComponents(&rsa);
	PKCS12_free(p12_struct);

	cryptKeysetClose(key_set);
	cryptDestroyContext(pKey);
	cryptDestroyCert(cert);

	return 0;
}
