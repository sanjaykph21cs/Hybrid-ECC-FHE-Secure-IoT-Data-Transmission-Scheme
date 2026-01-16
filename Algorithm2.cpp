/* ---------ECC-Based Encryption and Decryption Scheme--------- */

#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <iostream>
#include <vector>
#include <string>

using namespace std;

BIGNUM* stringToBN(const string &msg) {
    return BN_bin2bn((const unsigned char*)msg.c_str(), msg.size(), NULL);
}

string BNToString(const BIGNUM* bn) {
    int len = BN_num_bytes(bn);
    vector<unsigned char> buffer(len);
    BN_bn2bin(bn, buffer.data());
    return string(buffer.begin(), buffer.end());
}

EC_POINT* mapBNToPoint(const BIGNUM* bn, const EC_GROUP* group, BN_CTX* ctx) {
    EC_POINT* point = EC_POINT_new(group);
    EC_POINT_mul(group, point, bn, NULL, NULL, ctx); // point = bn * G
    return point;
}

BIGNUM* mapPointToBN(const EC_POINT* point, const EC_GROUP* group, BN_CTX* ctx) {
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, point, x, y, ctx);
    BN_free(y);
    return x; // Use x-coordinate as proxy for BIGNUM
}

int main() {
    BN_CTX* ctx = BN_CTX_new();

    // ----------Key Generation ----------
    EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!EC_KEY_generate_key(ecKey)) {
        cerr << "ECC Key Generation failed!" << endl;
        return 1;
    }

    const EC_GROUP* group = EC_KEY_get0_group(ecKey);
    const BIGNUM* sk = EC_KEY_get0_private_key(ecKey);
    const EC_POINT* pk = EC_KEY_get0_public_key(ecKey);

    string msg = "Hello ECC Enhanced!";
    cout << "Original message: " << msg << endl;

    // ---------- Message Mapping ----------
    BIGNUM* bn_msg = stringToBN(msg);
    EC_POINT* P_msg = mapBNToPoint(bn_msg, group, ctx);

    // ---------- Randomization ----------
    BIGNUM* ran = BN_new();
    BN_rand_range(ran, EC_GROUP_get0_order(group));

    EC_POINT* Cipher1 = EC_POINT_new(group);
    EC_POINT_mul(group, Cipher1, ran, NULL, NULL, ctx); 

    EC_POINT* temp = EC_POINT_new(group);
    EC_POINT_mul(group, temp, NULL, pk, ran, ctx);       

    EC_POINT* Cipher2 = EC_POINT_new(group);
    EC_POINT_add(group, Cipher2, temp, P_msg, ctx);      

    EC_POINT* C = EC_POINT_new(group);
    EC_POINT_mul(group, C, NULL, Cipher1, sk, ctx);      
    EC_POINT_invert(group, C, ctx);                      
    EC_POINT* recoveredPoint = EC_POINT_new(group);
    EC_POINT_add(group, recoveredPoint, Cipher2, C, ctx); // P_msg = Cipher2 + (-C)

    // ---------- Recover original string ----------
    BIGNUM* recoveredBN = mapPointToBN(recoveredPoint, group, ctx);
    string recoveredMsg = BNToString(recoveredBN);
    cout << "Recovered message: " << recoveredMsg << endl;
    EC_POINT_free(P_msg);
    EC_POINT_free(Cipher1);
    EC_POINT_free(Cipher2);
    EC_POINT_free(temp);
    EC_POINT_free(C);
    EC_POINT_free(recoveredPoint);
    BN_free(bn_msg);
    BN_free(ran);
    BN_free(recoveredBN);
    EC_KEY_free(ecKey);
    BN_CTX_free(ctx);

    return 0;
}



