//g++  open_ecdsa.cpp -o open -lssl -lcrypto -lstdc++

#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/bn.h>

#include <stdlib.h>  // for strtol
#include <math.h>
#include <string.h>

#include <cstdint>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <iomanip>


#define SIG_SIZE 64
#define PUB_KEY_SIZE 64
#define DIG_SIZE 32
#define PRIV_KEY_SIZE 32

using std::cout;
using std::cin;
using std::endl;
using std::vector;
using std::string;

// std::vector<uint8_t> Hash512(const std::string &str) {
//    std::cout << "SHA512 is used" <<std::endl;
//    std::cout << "Original Message is "<< STRING << std::endl;uint8_t>
//    std::cout << "The message hash output:\n";
//    std::cout << uint8_vector_to_hex_string(md) <<std::endl;
//   return md;
// }

std::vector<uint8_t> Hash256(const std::string &str) {
  // std::cout << "SHA256 is used" <<std::endl;
  // std::cout << "Original Message is "<< STRING << std::endl; 
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, str.c_str(), str.size());
  std::vector<uint8_t> md(SHA256_DIGEST_LENGTH);
  SHA256_Final(md.data(), &ctx);
  // std::cout << "The message hash output:\n";
  // std::cout << uint8_vector_to_hex_string(md) <<std::endl;
  return md;
}

void char_array_display (const char* char_ptr, int size, const char* msg)
{   for(int i = 0; i < size; i++)
    cout  << std::setw(1) << std::setfill('0') << static_cast<char>(tolower(*(char_ptr+i)));
    cout  << "  //" << msg <<   endl;
}

string sha256_string (const string str)
{   unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// string uint8_vector_to_hex_string(const string name, const vector<uint8_t>& v) {
string uint8_vector_to_hex_string(const vector<uint8_t>& v) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    std::vector<uint8_t>::const_iterator it;
    ss << "0x ";
    for (it = v.begin(); it != v.end(); it++) {
        ss << std::setw(2) << static_cast<unsigned>(*it);
    }
    return ss.str();
}

int main(int argc, char** argv)
{   
    if (argc != 2) {
        printf("Wrong usage: %s number\n", argv[0]);
        return 1;
        }
    char* argv_ptr;
    errno = 0; // not 'int errno', because the '#include' already defined it
    long arg = strtol(argv[1], &argv_ptr, 10); // string to long(string, endpointer, base)
    if (*argv_ptr != '\0' || errno != 0) {
        return 1; // In main(), returning non-zero means failure
        }
    if (arg < 0 || arg > INT_MAX) {
        return 1;
        }
    
    uint signature_number = arg;
    printf("let us make %d test vectors\n", signature_number);
    
    vector<uint8_t> Digest      (DIG_SIZE, 0);
    // vector<uint8_t> Signature_R (SIG_SIZE/2,0);
    // vector<uint8_t> Signature_S (SIG_SIZE/2,0);
    // vector<uint8_t> Pub_key_Qx  (PUB_KEY_SIZE/2,0);
    // vector<uint8_t> Pub_key_Qy  (PUB_KEY_SIZE/2,0);
    // vector<uint8_t> Private_key (PRIV_KEY_SIZE,0);
    vector<uint8_t> Signature_R;
    vector<uint8_t> Signature_S;
    vector<uint8_t> Pub_key_Qx;
    vector<uint8_t> Pub_key_Qy;
    vector<uint8_t> Private_Key;

    //const char *mesg_string = "Hello world!";
    const char *mesg_string = "aaa";
    cout << "Input Message is "<< mesg_string << std::endl;
    Digest=Hash256(mesg_string);
    cout << "Hash256(message) " << Digest.size() << " byte" <<endl;
    std::cout << uint8_vector_to_hex_string(Digest) <<std::endl;
    //9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0
 for (uint32_t i=0; i<signature_number; i++)    {
    printf("\n===========Signature body #%d of #%d ===============\n",i,signature_number);
    EC_KEY *ec_key = EC_KEY_new();
       if (ec_key == NULL)  {
        cout<< "Error happen for creating ECC key object!" <<endl;
            return false;
        }
    EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(714);   //NID_secp256k1
    EC_KEY_set_group(ec_key, ec_group);

    int ret=EC_KEY_generate_key(ec_key);
    if (ret == 0)    {
         cout<< "Error happen for creating ECC key pair!" <<endl;
            return false;
        }
    
    const EC_POINT *pub = EC_KEY_get0_public_key(ec_key);
    const BIGNUM *privkey = EC_KEY_get0_private_key(ec_key);
    BIGNUM *Qx = BN_new();
    BIGNUM *Qy = BN_new();
    //char *

    if (EC_POINT_get_affine_coordinates_GFp(ec_group, pub, Qx, Qy, NULL)) {
        cout << "Pub key generated:\n";
        // cout << "Qx      : ";
        // BN_print_fp(stdout, Qx);
        // putc('\n', stdout);
        // cout << "Qy      : ";
        // BN_print_fp(stdout, Qy);
        // putc('\n', stdout);
        // cout << "Priv key: ";
        // BN_print_fp(stdout, privkey);
        // cout <<"\n";
    }
    
    ECDSA_SIG *signature;
    unsigned char *dig_ptr=Digest.data();
    signature = ECDSA_do_sign(dig_ptr, SHA256_DIGEST_LENGTH, ec_key);
     if (signature == NULL)
     {cout <<"Signature generation fail!\n";
        return false;
        }
    const BIGNUM *pr = BN_new();
    const BIGNUM *ps = BN_new();

    ret = ECDSA_do_verify(dig_ptr, SHA256_DIGEST_LENGTH, signature, ec_key);
    // ret = ECDSA_verify(0, digest, 32, buffer, buf_len, ec_key);
        if (ret == 1)
        {cout << "The signature verified OK:\n" <<endl;
             }
        else if (ret == 0)
        {cout << "The signature verified fail!:\n" <<endl;
            return false;
            }
        else
        {cout << "The signature verified unnormal, err code=" <<ret <<"/n";
            return false;
            }

    ECDSA_SIG_get0(signature, &pr, &ps);
        // cout << "Sig   :\n";
        // cout << "Sig.r : ";
        // BN_print_fp(stdout, pr);
        // putc('\n', stdout);
        // cout << "Sig.s : ";
        // BN_print_fp(stdout, ps);
        // putc('\n', stdout);
        // putc('\n', stdout);

    //char *BN_bn2hex(const BIGNUM *a);
    // Signature_R.data()= BN_bn2hex (pr);
    // Signature_S.data()= BN_bn2hex (ps);
    // char *BN_bn2dec(const BIGNUM *a);
// Convert from BIGNUM to Hex String.
 //
    // cout << "================  low case disply  ===================\n";
    // cout << "Input Message is "<< mesg_string << std::endl;
    //cout << "Hash256(message) " << Digest.size() << " byte" <<endl;
    // std::cout << uint8_vector_to_hex_string(Digest) <<" //Digest" <<std::endl;

    char* Q_x   = BN_bn2hex(Qx);
    char* Q_y   = BN_bn2hex(Qy);
    char* sig_r = BN_bn2hex(pr);
    char* sig_s = BN_bn2hex(ps);
    //char* priv_key = BN_bn2hex(priv_key);

    // char_array_display (sig_r,SIG_SIZE,"sig.r");
    char_array_display (sig_r,SIG_SIZE,"sig.r");
    char_array_display (sig_s,SIG_SIZE,"sig.s");
    char_array_display (Q_x,   PUB_KEY_SIZE,"QX");
    char_array_display (Q_y,   PUB_KEY_SIZE,"QY");

    // for(int i = 0; i < PRIV_KEY_SIZE; i++)
    // {    
    //     cout  << std::setw(1) << std::setfill('0') << tolower(*(priv_key+i));
    // }
    //     cout<< " //Priv Key" <<endl;
        
    // int i=0;

    // for(vector<uint8_t>::iterator it=Signature_R.begin(); it != Signature_R.end(); it++)
    // {
    //     *it << *(sig_r+i);
    //     i++;
    // }
    //cout<<uint8_vector_to_hex_string(Signature_R);

    OPENSSL_free(sig_r);
    OPENSSL_free(sig_s);
    OPENSSL_free(Q_x);
    OPENSSL_free(Q_y);
    sig_r = nullptr;
    sig_s = nullptr;
    Q_x   = nullptr;
    Q_y   = nullptr;
    }//end of iteration;
 

    // BN_free(Qx);
    // BN_free(Qy);
    // BN_free(pr);
    // BN_free(ps);
    // BN_free(privkey);

     return 0;
}
