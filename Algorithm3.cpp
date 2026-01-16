/* -------- Hybrid ECC-FHE Secure IoT Data Transmission -------- */

#include <helib/helib.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
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

EC_POINT* eccEncrypt(EC_GROUP* group, const EC_POINT* pk, BIGNUM* msgBN, BN_CTX* ctx, BIGNUM* ran, EC_POINT*& C1, EC_POINT*& C2)
{
    C1 = EC_POINT_new(group);
    EC_POINT_mul(group, C1, ran, NULL, NULL, ctx);
    EC_POINT* Pmsg = EC_POINT_new(group);
    EC_POINT_mul(group, Pmsg, msgBN, NULL, NULL, ctx);
    EC_POINT* ranPK = EC_POINT_new(group);
    EC_POINT_mul(group, ranPK, NULL, pk, ran, ctx);
    C2 = EC_POINT_new(group);
    EC_POINT_add(group, C2, Pmsg, ranPK, ctx);
    EC_POINT_free(Pmsg);
    EC_POINT_free(ranPK);

    return C2;
}

EC_POINT* eccDecrypt(EC_GROUP* group, EC_POINT* C1, EC_POINT* C2, BIGNUM* sk, BN_CTX* ctx)
{
    EC_POINT* C = EC_POINT_new(group);
    EC_POINT_mul(group, C, NULL, C1, sk, ctx);
    EC_POINT_invert(group, C, ctx);
    EC_POINT* Pmsg_rec = EC_POINT_new(group);
    EC_POINT_add(Pmsg_rec, C2, C, ctx);
    EC_POINT_free(C);
    return Pmsg_rec;
}

void runHybridECCFHE(int keySize, double& encTime, double& decTime)
{
    auto t1 = high_resolution_clock::now();

    // ECC Key Generation
    EC_KEY* deviceKey = generateECCKey();
    EC_KEY* userKey   = generateECCKey();
    const EC_GROUP* group = EC_KEY_get0_group(deviceKey);
    BN_CTX* ctx = BN_CTX_new();

    if (!eccAuth(deviceKey, "DEV") || !eccAuth(userKey, "USR"))
    {
        cout << "Authentication failed!" << endl;
        return;
    }
    const BIGNUM* pk_d_bn = EC_KEY_get0_private_key(deviceKey);
    BIGNUM* msgBN = BN_new();
    BN_set_word(msgBN, 42);
    BIGNUM* ran = BN_new();
    BN_rand_range(ran, EC_GROUP_get0_order(group));
    const EC_POINT* pk_ec = EC_KEY_get0_public_key(deviceKey);
    EC_POINT* C1 = nullptr;
    EC_POINT* C2 = nullptr;
    eccEncrypt((EC_GROUP*)group, pk_ec, msgBN, ctx, ran, C1, C2);

    // Extract x-coordinate of C1 and C2 for FHE encryption
    BIGNUM* C1_x = BN_new();
    BIGNUM* C2_x = BN_new();
    BIGNUM* y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, C1, C1_x, y, ctx);
    EC_POINT_get_affine_coordinates_GFp(group, C2, C2_x, y, ctx);
    BN_free(y);
    long C1_int = BN_get_word(C1_x);
    long C2_int = BN_get_word(C2_x);

    helib::Context context = helib::ContextBuilder<helib::BGV>()
                                .m(keySize).p(4999).r(1).bits(300)
                                .build();
    helib::SecKey sk(context);
    sk.GenSecKey();
    const helib::PubKey& pk_fhe = sk;
    helib::Ptxt<helib::BGV> ptxt1(context, C1_int);
    helib::Ptxt<helib::BGV> ptxt2(context, C2_int);
    helib::Ctxt ctxt1(pk_fhe);
    helib::Ctxt ctxt2(pk_fhe);
    pk_fhe.Encrypt(ctxt1, ptxt1);
    pk_fhe.Encrypt(ctxt2, ptxt2);

    auto t2 = high_resolution_clock::now();
    encTime = duration_cast<milliseconds>(t2 - t1).count();
    ctxt1 += ctxt1; 
    ctxt2 += ctxt2;

    // Decryption and recovery of message
    helib::Ptxt<helib::BGV> dec1(context);
    helib::Ptxt<helib::BGV> dec2(context);
    sk.Decrypt(dec1, ctxt1);
    sk.Decrypt(dec2, ctxt2);

    long dec_C1_int = dec1[0];
    long dec_C2_int = dec2[0];
    BIGNUM* dec_C1_bn = BN_new(); BN_set_word(dec_C1_bn, dec_C1_int);
    BIGNUM* dec_C2_bn = BN_new(); BN_set_word(dec_C2_bn, dec_C2_int);

    EC_POINT* C1_dec = EC_POINT_new((EC_GROUP*)group);
    EC_POINT* C2_dec = EC_POINT_new((EC_GROUP*)group);
    EC_POINT_set_compressed_coordinates_GFp((EC_GROUP*)group, C1_dec, dec_C1_bn, 0, ctx);
    EC_POINT_set_compressed_coordinates_GFp((EC_GROUP*)group, C2_dec, dec_C2_bn, 0, ctx);
    EC_POINT* Pmsg_dec = eccDecrypt((EC_GROUP*)group, C1_dec, C2_dec, (BIGNUM*)pk_d_bn, ctx);
    auto t4 = high_resolution_clock::now();
    decTime = duration_cast<milliseconds>(t4 - t2).count();
  
    EC_KEY_free(deviceKey);
    EC_KEY_free(userKey);
    BN_free(msgBN); BN_free(ran);
    BN_free(C1_x); BN_free(C2_x);
    BN_free(dec_C1_bn); BN_free(dec_C2_bn);
    EC_POINT_free(C1); EC_POINT_free(C2);
    EC_POINT_free(C1_dec); EC_POINT_free(C2_dec);
    EC_POINT_free(Pmsg_dec);
    BN_CTX_free(ctx);
}
int main()
{
    vector<int> keySizes = {512, 1024, 1536, 2048, 2560};
    cout << "\n Proposed Hybrid Scheme’s Encryption and Decryption Time \n";
    cout << "KeySize\tEnc(ms)\tDec(ms)\n";
    for (int k : keySizes)
    {
        double encTime = 0, decTime = 0;
        runHybridECCFHE(k, encTime, decTime);
        cout << k << "\t" << encTime << "\t" << decTime << endl;
    }
    return 0;
}

