#pragma once

#include "Common.h"


class Analyst
{

    public:

        Analyst(vector<int64_t> weights, vector<int64_t> bias)
	{
		w = weights;
		b = bias;

		context = get_seal_context(config::plain_mod, config::mod_degree, config::seclevel);
		keygen = new KeyGenerator(*context);
		he_benc = new BatchEncoder(*context);	
	}

        shared_ptr<SEALContext> getContext() { return context; }

        BatchEncoder* getBatchEncoder() { return he_benc; }

        Encryptor* getEncryptor() { return he_enc; }

        PublicKey getPublicKey() { return he_pk; }

        RelinKeys getRelinKeys() { return he_rk; }

        GaloisKeys getGaloisKeys() { return he_gk; }

        Ciphertext getEncryptedWeights() { return w_c; }

        Ciphertext getEncryptedBiases() { return b_c; }

        void generateHEKeys();

        void encryptData();

        void decryptData(Ciphertext c_res);
        void decryptData(seal_byte* bytes, int size);

        int getPublicKeyBytes(seal_byte* &);
        int getRelinKeysBytes(seal_byte* &);
        int getGaloisKeysBytes(seal_byte* &);

        int getEncWeightsBytes(seal_byte* &);
        int getEncBiasBytes(seal_byte* &);


    private:

        shared_ptr<SEALContext> context;

        PublicKey he_pk;
        SecretKey he_sk;
        RelinKeys he_rk;
        GaloisKeys he_gk;

        vector<int64_t> w; // dummy weights
        vector<int64_t> b; // dummy biases
        Ciphertext w_c; // the encrypted weights
        Ciphertext b_c; // the encrypted bias

        vector<int64_t> result;

        KeyGenerator* keygen;
        BatchEncoder* he_benc;

        Encryptor* he_enc;
};
