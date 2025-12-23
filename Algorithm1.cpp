/* ---------------- Lightweight and Secure Scheme with FHE and Dual Authentication ---------------- */

#include <helib/helib.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <chrono>
#include <iostream>
using namespace std;
using namespace std::chrono;
EC_KEY* generateECCKey()
{
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(key);
    return key;
}
bool eccSignVerify(EC_KEY* key)
{
    unsigned char msg[32] = "DEVICE_ID_01";
    unsigned char sig[256];
    unsigned int sigLen;

    // Sign
    if (!ECDSA_sign(0, msg, sizeof(msg), sig, &sigLen, key))
        return false;

    // Verify
    return ECDSA_verify(0, msg, sizeof(msg), sig, sigLen, key) == 1;
}
/* ---------------- ALGORITHM-1 CORE ---------------- */

void runAlgorithm1(int keySize, double& encTime, double& decTime)
{
    auto t1 = high_resolution_clock::now();
    /* --------- FHE KEY GENERATION --------- */
    long p = 4999;
    long m = keySize;
    long r = 1;
    long bits = 300;

    helib::Context context =
        helib::ContextBuilder<helib::BGV>()
        .m(m).p(p).r(r).bits(bits)
        .build();
    helib::SecKey sk(context);
    sk.GenSecKey();
    const helib::PubKey& pk = sk;

    /* --------- DUAL AUTHENTICATION --------- */
    EC_KEY* deviceKey = generateECCKey();

    if (!eccSignVerify(deviceKey)) {
        cout << "Authentication failed\n";
        EC_KEY_free(deviceKey);
        return;
    }

    /* --------- ENCRYPTION --------- */
    helib::Ptxt<helib::BGV> ptxt(context, 42);
    helib::Ctxt ctxt(pk);
    pk.Encrypt(ctxt, ptxt);
    auto t2 = high_resolution_clock::now();

    /* --------- CLOUD COMPUTATION --------- */
    ctxt += ctxt;   // Eval(pk, F, c)
    auto t3 = high_resolution_clock::now();
    /* --------- DECRYPTION --------- */
    helib::Ptxt<helib::BGV> result(context);
    sk.Decrypt(result, ctxt);
    auto t4 = high_resolution_clock::now();
    encTime =
        duration_cast<milliseconds>(t2 - t1).count();
    decTime =
        duration_cast<milliseconds>(t4 - t3).count();
    EC_KEY_free(deviceKey);
}
int main()
{
    vector<int> keySizes = {512, 1024, 1536, 2048, 2560};
    cout << "\nAlgorithm-1: Lightweight ECC + FHE Scheme\n";
    cout << "KeySize\tEnc(ms)\tDec(ms)\n";

    for (int k : keySizes) {
        double enc, dec;
        runAlgorithm1(k, enc, dec);
        cout << k << "\t" << enc << "\t" << dec << endl;
    }
    return 0;
}

