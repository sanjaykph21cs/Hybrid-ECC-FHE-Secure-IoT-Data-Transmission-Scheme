/* ---------Hybrid ECC-FHE Secure IoT Data Transmission Scheme--------- */

#include <helib/helib.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <chrono>
#include <iostream>
#include <vector>
#include <numeric>

using namespace std;
using namespace std::chrono;

#define RUNS 20

EC_KEY* generateECCKey()
{
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(key);
    return key;
}
bool eccAuth(EC_KEY* key, const string& id)
{
    unsigned char sig[256];
    unsigned int sigLen;

    if (!ECDSA_sign(0,
        (const unsigned char*)id.c_str(), id.size(),
        sig, &sigLen, key))
        return false;
    return ECDSA_verify(0,
        (const unsigned char*)id.c_str(), id.size(),
        sig, sigLen, key) == 1;
}

void runAlgorithm3(int keySize, double& encAvg, double& decAvg)
{
    vector<double> encTimes, decTimes;
    for (int r = 0; r < RUNS; r++) {

        /* ---------- ENCRYPTION START ---------- */
        auto t1 = high_resolution_clock::now();

        /* ECC key generation */
        EC_KEY* deviceKey = generateECCKey();
        EC_KEY* userKey   = generateECCKey();

        /* Dual authentication */
        if (!eccAuth(deviceKey, "DEV") ||  !eccAuth(userKey, "USR")) {
            continue;
        }

        /* ECC encryption */
        EC_GROUP* group =
            EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        BN_CTX* ctx = BN_CTX_new();

        BIGNUM* ran = BN_new();
        BN_rand_range(ran, EC_GROUP_get0_order(group));

        EC_POINT* C1 = EC_POINT_new(group);
        EC_POINT_mul(group, C1, ran, NULL, NULL, ctx);

        EC_POINT* Pub = EC_KEY_get0_public_key(deviceKey);
        EC_POINT* ranPub = EC_POINT_new(group);
        EC_POINT_mul(group, ranPub, NULL, Pub, ran, ctx);

        EC_POINT* Pmsg = EC_POINT_new(group);
        BIGNUM* msgBN = BN_new();
        BN_set_word(msgBN, 42);
        EC_POINT_mul(group, Pmsg, msgBN, NULL, NULL, ctx);

        EC_POINT* C2 = EC_POINT_new(group);
        EC_POINT_add(group, C2, ranPub, Pmsg, ctx);

        /* FHE key generation */
        helib::Context context =
            helib::ContextBuilder<helib::BGV>()
            .m(keySize).p(4999).r(1).bits(300)
            .build();

        helib::SecKey sk(context);
        sk.GenSecKey();
        const helib::PubKey& pk = sk;

        /* FHE encryption */
        helib::Ptxt<helib::BGV> ptxt(context, 1);
        helib::Ctxt ctxt(pk);
        pk.Encrypt(ctxt, ptxt);

        auto t2 = high_resolution_clock::now();
        encTimes.push_back(
            duration_cast<milliseconds>(t2 - t1).count());

        /* ---------- DECRYPTION START ---------- */
        auto t3 = high_resolution_clock::now();

        /* Cloud computation */
        ctxt += ctxt;

        /* FHE decryption */
        helib::Ptxt<helib::BGV> res(context);
        sk.Decrypt(res, ctxt);

        /* ECC decryption */
        BIGNUM* Sec = BN_new();
        BN_rand_range(Sec, EC_GROUP_get0_order(group));

        EC_POINT* C = EC_POINT_new(group);
        EC_POINT_mul(group, C, NULL, C1, Sec, ctx);
        EC_POINT_invert(group, C, ctx);

        EC_POINT* Pmsg_rec = EC_POINT_new(group);
        EC_POINT_add(group, Pmsg_rec, C2, C, ctx);

        auto t4 = high_resolution_clock::now();
        decTimes.push_back(
            duration_cast<milliseconds>(t4 - t3).count());

        EC_KEY_free(deviceKey);
        EC_KEY_free(userKey);
        EC_GROUP_free(group);
        BN_CTX_free(ctx);
        BN_free(ran);
        BN_free(msgBN);
        BN_free(Sec);
        EC_POINT_free(C1);
        EC_POINT_free(C2);
        EC_POINT_free(Pmsg);
        EC_POINT_free(Pmsg_rec);
        EC_POINT_free(C);
    }

    encAvg = accumulate(encTimes.begin(), encTimes.end(), 0.0) / RUNS;
    decAvg = accumulate(decTimes.begin(), decTimes.end(), 0.0) / RUNS;
}

int main()
{
    vector<int> keySizes = {512,1024,1536,2048,2560};
    cout << "\n Proposed Hybrid Scheme’s Encryption and Decryption Time\n";
    cout << "KeySize\tEnc(ms)\tDec(ms)\n";
    for (int k : keySizes)
  {
        double encT, decT;
        runAlgorithm3(k, encT, decT);
        cout << k << "\t" << encT << "\t" << decT << endl;  
    }

    cout << "\n Proposed Hybrid Scheme’s Encryption and Decryption Throughput\n";
    cout << "KeySize\tEnc_Throughput (bps)\tDec_ Throughput (bps)\n";
    for (int k : keySizes)
  {
        double encT, decT;
        runAlgorithm3(k, encT, decT);
        double encTP = k / (encT / 1000.0);
        double decTP = k / (decT / 1000.0);
        cout << k << "\t" << encTP/1000 << "\t" << decTP/1000 << endl;
    }
    return 0;
}


