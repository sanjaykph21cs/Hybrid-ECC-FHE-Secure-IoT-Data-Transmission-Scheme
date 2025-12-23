/* ---------ECC-Based Encryption and Decryption Scheme--------- */

#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <iostream>
using namespace std;

EC_GROUP* createCurve()
{
    return EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
}
BIGNUM* randomScalar(const EC_GROUP* group)
{
    BIGNUM* k = BN_new();
    BN_rand_range(k, EC_GROUP_get0_order(group));
    return k;
}
void Algorithm2_ECC(int msg)
{
    /* --------- Key Generation --------- */
    EC_GROUP* group = createCurve();
    BN_CTX* ctx = BN_CTX_new();

    BIGNUM* Sec = randomScalar(group);          // Private key
    EC_POINT* Pub = EC_POINT_new(group);        // Public key
    
    EC_POINT_mul(group, Pub, Sec, NULL, NULL, ctx);

    /* --------- Message Mapping --------- */
    
    EC_POINT* Pmsg = EC_POINT_new(group);
    BIGNUM* msgBN = BN_new();
    BN_set_word(msgBN, msg);
    EC_POINT_mul(group, Pmsg, msgBN, NULL, NULL, ctx);
    BIGNUM* ran = randomScalar(group);
    EC_POINT* C1 = EC_POINT_new(group);
    EC_POINT_mul(group, C1, ran, NULL, NULL, ctx);

    /* --------ENCRYPTION METHOD 1---------     */

    EC_POINT* ranPub = EC_POINT_new(group);
    EC_POINT_mul(group, ranPub, NULL, Pub, ran, ctx);
    EC_POINT* C2 = EC_POINT_new(group);
    EC_POINT_add(group, C2, ranPub, Pmsg, ctx);

    /* --------- DECRYPTION METHOD 1 --------- */
    EC_POINT* C = EC_POINT_new(group);
    EC_POINT_mul(group, C, NULL, C1, Sec, ctx);

    EC_POINT* Pmsg_rec = EC_POINT_new(group);
    EC_POINT_invert(group, C, ctx);
    EC_POINT_add(group, Pmsg_rec, C2, C, ctx);
    cout << "Method-1 ECC encryption/decryption completed\n";

    /* ---------  ENCRYPTION METHOD 2 ------------*/

    EC_POINT* C2m2 = EC_POINT_new(group);
    EC_POINT_mul(group, C2m2, NULL, Pub, ran, ctx);
    BIGNUM* C3 = BN_new();
    BN_mul(C3, msgBN, ran, ctx);

    /* --------- DECRYPTION METHOD 2 --------- */
    
    BIGNUM* C2inv = BN_mod_inverse(NULL, ran,
        EC_GROUP_get0_order(group), ctx);

    BIGNUM* msg_rec = BN_new();
    BN_mod_mul(msg_rec, C3, C2inv,
        EC_GROUP_get0_order(group), ctx);

    cout << "Recovered msg (Method-2): "
         << BN_get_word(msg_rec) << endl;

    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    BN_free(Sec);
    EC_POINT_free(Pub);
    EC_POINT_free(Pmsg);
    EC_POINT_free(C1);
    EC_POINT_free(C2);
    EC_POINT_free(C);
    EC_POINT_free(Pmsg_rec);
    BN_free(msgBN);
    BN_free(ran);
    BN_free(C3);
    BN_free(C2inv);
    BN_free(msg_rec);
}
int main()
{
    int msg = 25;
    Algorithm2_ECC(msg);
    return 0;
}

