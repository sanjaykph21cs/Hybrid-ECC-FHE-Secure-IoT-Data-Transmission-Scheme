/* ---------------- Lightweight Authentication with FHE Encryption and Decryption ---------------- */

#include <helib/helib.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <iostream>

using namespace std;

/* ---------------- ECC Key Generation ---------------- */
EC_KEY* generateECCKey()
{
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(key);
    return key;
}

/* ---------------- ECC Sign and Verify ---------------- */
bool eccAuthenticate(EC_KEY* key, const unsigned char* msg, size_t msgLen)
{
    unsigned char signature[256];
    unsigned int sigLen = 0;

    /* Sign message */
    if (!ECDSA_sign(0, msg, msgLen, signature, &sigLen, key))
        return false;

    /* Verify signature */
    int verifyStatus =
        ECDSA_verify(0, msg, msgLen, signature, sigLen, key);

    return (verifyStatus == 1);
}

int main()
{
    /* ---------------- Input ---------------- */
    long m_val = 42;                   // Plaintext message m
    const unsigned char ID_dev[] = "DEVICE_ID_01";
    long lambda_bits = 300;             // Security parameter λ

    /* ---------------- ECC-Based Authentication ---------------- */
    cout << "Performing ECC-based device authentication...\n";

    EC_KEY* deviceKey = generateECCKey();

    if (!eccAuthenticate(deviceKey, ID_dev, sizeof(ID_dev)))
    {
        cout << "Authentication Failed! Access denied.\n";
        EC_KEY_free(deviceKey);
        return 0;
    }

    cout << "Authentication Successful.\n";

    /* ---------------- FHE Setup (HElib) ---------------- */
    long p = 4999;      // Plaintext modulus
    long m = 1024;      // Cyclotomic order
    long r = 1;         // Lifting parameter

    helib::Context context =
        helib::ContextBuilder<helib::BGV>()
            .m(m)
            .p(p)
            .r(r)
            .bits(lambda_bits)
            .build();

    /* ---------------- FHE Key Generation ---------------- */
    helib::SecKey sk(context);
    sk.GenSecKey();
    const helib::PubKey& pk = sk;

    /* ---------------- FHE Encryption ---------------- */
    helib::Ptxt<helib::BGV> ptxt(context, m_val);
    helib::Ctxt ctxt(pk);
    pk.Encrypt(ctxt, ptxt);

    /* ---------------- Homomorphic Evaluation ---------------- */
    // Example function f(m) = m + m
    ctxt += ctxt;

    /* ---------------- FHE Decryption ---------------- */
    helib::Ptxt<helib::BGV> ptxt_dec(context);
    sk.Decrypt(ptxt_dec, ctxt);

    cout << "\nFHE Processing Results:\n";
    cout << "Original Plaintext  : " << m_val << endl;
    cout << "Decrypted Plaintext : " << ptxt_dec[0] << endl;

    EC_KEY_free(deviceKey);
    return 0;
}
