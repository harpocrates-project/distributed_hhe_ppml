#pragma once

#include "Common.h"

class User
{
    
    public:

        User(vector<uint64_t> plaintext) 
        {
            x_i = plaintext;

            context = get_seal_context(config::plain_mod, config::mod_degree, config::seclevel);
            he_benc = new BatchEncoder(*context);
        }

        void generateSymmetricKey();

        void printData();

        void encryptData();

	void getAnalystKey(string analistAddress);

        void encryptSymmetricKey(seal_byte* he_pk_bytes, int size);

        vector<Ciphertext> getEncryptedSymmetricKeys() { return c_k; }

        vector<uint64_t> getEncryptedData() { return c_i; }


        int getEncSymmetricKeyBytes(seal_byte* &buffer, int index);



    private:

        shared_ptr<SEALContext> context;
        BatchEncoder* he_benc;

        vector<uint64_t> ssk; // the secret symmetric key
        vector<Ciphertext> c_k; // the HE encrypted symmetric keys    

        vector<uint64_t> x_i; //plaintext data
        vector<uint64_t> c_i; // symmetric encrypted x_i

	PublicKey* he_pk;
};
