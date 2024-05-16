#pragma once

#include "../../Common.h"

class User{
    public:
        void loadDataAndLabel();

        //setter
        void setUserSymmetricKey(); // client_sym_key
        // getter
        vector<uint64_t> getUserSymmetricKey(); // client_sym_key

        void encryptData(vector<uint64_t> client_sym_key); // data encryption

        void encryptSymmetricKey(seal_byte* he_pk_bytes, int size); // user's symmetric key encryption
   
    private:
        matrix::matrix data;    
        matrix::matrix labels; 
        matrix::vector vi; // plaintext data
        vector<uint64_t> vi_se; // symmetric encrypted vi
        vector<uint64_t> client_sym_key; // User's symmetric key
        vector<seal::Ciphertext> client_hhe_key // User's encrypted symmetric key
};