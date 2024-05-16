#pragma once

#include "../../Common.h"

class Analyst
{
    public:

        Analyst(){
		    context = get_seal_context(config::plain_mod, config::mod_degree, config::seclevel);	
	    }

        // setter
        void setKeyGenerator(); // keygen
        void setBatchEncoder(); // he_benc
        void setAnalystHeSecretKey(KeyGenerator* keygen); // he_sk
        void setAnalystHePublicKey(KeyGenerator* keygen); // he_pk
        void setAnalystHeRelinKeys(KeyGenerator* keygen); // he_rk
        void setAnalystHeGaloisKeys(BatchEncoder* he_benc, KeyGenerator* keygen);  // he_gk
        void setEncryptor(); // encryptor
        void setEvaluator(); // evaluator
        void setDecryptor(); // decryptor

        // getter
        KeyGenerator* getKeyGenerator(); // keygen
        BatchEncoder* getBatchEncoder(); // he_benc
        SecretKey getAnalystHeSecretKey(); // he_sk
        PublicKey getAnalystHePublicKey(); // he_pk
        RelinKeys getAnalystHeRelinKeys(); // he_rk
        GaloisKeys getAnalystHeGaloisKeys(); // he_gk    
        Encryptor* getEncryptor(); // he_enc
        Evaluator* getEvaluator(); // he_eval
        Decryptor* getDecryptor(); // he_dec
        shared_ptr<SEALContext> getContext();

        // functions
        void heInitialization();

        void generateHEKeys();

        int getPublicKeyBytes(seal_byte* &);

    private:

        shared_ptr<SEALContext> context;

        PublicKey he_pk;
        SecretKey he_sk;
        RelinKeys he_rk;
        GaloisKeys he_gk;

        KeyGenerator* keygen;
        BatchEncoder* he_benc;

        Encryptor* he_enc;
        Evaluator* he_eval;
        Decryptor* he_dec;
};