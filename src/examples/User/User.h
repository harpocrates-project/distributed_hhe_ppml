#pragma once

#include "../../Common.h"

class User{
    public:
        User(){
            context = get_seal_context(config::plain_mod, config::mod_degree, config::seclevel);
            he_benc = new BatchEncoder(*context);
        }

        void loadDataAndLabel();

        //setter
        void setUserSymmetricKey(); // client_sym_key
        // getter
        vector<uint64_t> getUserSymmetricKey(); // client_sym_key

        void encryptData(vector<uint64_t> client_sym_key); // data encryption

        void encryptSymmetricKey(vector<uint64_t> client_sym_key, seal_byte* he_pk_bytes, int size); // user's symmetric key encryption
   
        vector<Ciphertext> getEncryptedSymmetricKeys();

        vector<uint64_t> getEncryptedData();

        int getEncSymmetricKeyBytes(seal_byte* &buffer, int index);

        void computingCheck();

        void print_vec_Ciphertext(std::vector<seal::Ciphertext> input, size_t size);
    
    private:
        shared_ptr<SEALContext> context;
        BatchEncoder* he_benc;

        matrix::matrix data;    
        matrix::matrix labels; 
        matrix::vector vi; // plaintext data
        vector<uint64_t> vi_se; // symmetric encrypted vi
        vector<uint64_t> client_sym_key; // User's symmetric key
        vector<seal::Ciphertext> client_hhe_key; // User's encrypted symmetric key (c_k)
};