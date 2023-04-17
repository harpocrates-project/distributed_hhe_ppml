#include "Analyst.h"
#include "../tests/he_test.cpp"


void Analyst::generateHEKeys()
{
    print_parameters(*context);

    cout << "[Analyst] Creating HE keys, batch encoder, encryptor and evaluator from the context" << endl;
    
    he_sk = keygen->secret_key(); // HE Decryption Secret Key
    keygen->create_public_key(he_pk);
    keygen->create_relin_keys(he_rk);
    
    bool use_bsgs = false;
    vector<int> gk_indices = add_gk_indices(use_bsgs, *he_benc);
    keygen->create_galois_keys(gk_indices, he_gk);

    he_enc = new Encryptor(*context, he_pk);
}


void Analyst::encryptData()
{
    cout << "[Analyst] Encrpyting weights and biases" << endl;
    print_vec(w, w.size(), "[Analyst] weights");
    print_vec(b, b.size(), "[Analyst] bias");

    w_c = encrypting(w, he_pk, *he_benc, *he_enc);
    b_c = encrypting(b, he_pk, *he_benc, *he_enc);
    vector<int64_t> w_d = decrypting(w_c, he_sk, *he_benc, *context, w.size());
    vector<int64_t> b_d = decrypting(b_c, he_sk, *he_benc, *context, b.size());

    cout << "[Analyst] Decrypting weights and biases to check" << endl;
    TEST::he_enc_dec_test(w, w_d);
    TEST::he_enc_dec_test(b, b_d);
}

void Analyst::decryptData(Ciphertext c_res )
{
    result = decrypting(c_res, he_sk, *he_benc, *context, w.size());
    print_vec(result, result.size(), "decrypted result");
}


void Analyst::decryptData(seal_byte* bytes, int size)
{
    cout << "[Analyst] Decrypting results received from CSP" << endl;

    /*
    for (int i = 0; i < 10; i++) {
        std::cout << (int)bytes[i] << ' ';
    }
    cout << endl;
    */

    Ciphertext* c_res = new Ciphertext();
    c_res->load(*context, bytes, size);

    result = decrypting(*c_res, he_sk, *he_benc, *context, w.size());
    print_vec(result, result.size(), "[Analyst] decrypted result");
}



int Analyst::getPublicKeyBytes(seal_byte* &buffer)
{
    int he_pk_size = he_pk.save_size();
    buffer = new seal_byte[he_pk_size];
    he_pk.save(buffer, he_pk_size);

    cout << "[Analyst] Serialising Public Key (size=" << he_pk_size << ")" << endl;

    /*
    for (int i = 0; i < 10; i++) {
        std::cout << (int)buffer[i] << ' ';
    }
    cout << endl;
    */

    return he_pk_size;
}


int Analyst::getRelinKeysBytes(seal_byte* &buffer)
{
    int he_rk_size = he_rk.save_size();
    buffer = new seal_byte[he_rk_size];
    he_rk.save(buffer, he_rk_size);

    cout << "[Analyst] Serialising Relin Key (size=" << he_rk_size << ")" << endl;

    /*
    for (int i = 0; i < 10; i++) {
        std::cout << (int)buffer[i] << ' ';
    }
    cout << endl;
    */

    return he_rk_size;
}

int Analyst::getGaloisKeysBytes(seal_byte* &buffer)
{
    int he_gk_size = he_gk.save_size();
    buffer = new seal_byte[he_gk_size];
    he_gk.save(buffer, he_gk_size);

    cout << "[Analyst] Serialising Galois Key (size=" << he_gk_size << ")" << endl;

    /*
    for (int i = 0; i < 10; i++) {
        std::cout << (int)buffer[i] << ' ';
    }
    cout << endl;
    */

    return he_gk_size;
}


int Analyst::getEncWeightsBytes(seal_byte* &buffer)
{
    int w_c_size = w_c.save_size();
    buffer = new seal_byte[w_c_size];
    w_c.save(buffer, w_c_size);

    cout << "[Analyst] Serialising Encrypted Weights (size=" << w_c_size << ")" << endl;

    /*
    for (int i = 0; i < 10; i++) {
        std::cout << (int)buffer[i] << ' ';
    }
    cout << endl;
    */

    return w_c_size;
}

int Analyst::getEncBiasBytes(seal_byte* &buffer)
{
    int b_c_size = b_c.save_size();
    buffer = new seal_byte[b_c_size];
    b_c.save(buffer, b_c_size);

    cout << "[Analyst] Serialising Encrypted Bias (size=" << b_c_size << ")" << endl;

    /*
    for (int i = 0; i < 10; i++) {
        std::cout << (int)buffer[i] << ' ';
    }
    cout << endl;
    */

    return b_c_size;
}
