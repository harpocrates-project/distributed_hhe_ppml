#pragma once
#include <unordered_map>

#include "../../Common.h"


class CSP
{
    public:

        CSP() 
        {
            context = get_seal_context(config::plain_mod, config::mod_degree, config::seclevel);
        }

        // setter
        void setKeyGenerator(); // keygen
        void setEvaluator(); // evaluator
        void setCSPHeSecretKey(KeyGenerator* keygen); // he_sk

        // getter
        KeyGenerator* getKeyGenerator(); // keygen
        Evaluator* getEvaluator(); // he_eval
        SecretKey getCSPHeSecretKey(); // he_sk

        // functions
        void heInitialization();
        

        bool addPublicKey(string analystId, seal_byte* bytes, int size);
        bool addRelinKey(string analystId, seal_byte* bytes, int size);
        bool addGaloisKey(string analystId, seal_byte* bytes, int size);

        bool addEncSymKeys(string analystId, vector<seal_byte*> bytes, vector<int> lengths);

    private:
    
        shared_ptr<SEALContext> context;
        Evaluator* he_eval;

        KeyGenerator* keygen;
        SecretKey he_sk;

        //vector<Ciphertext> c_prime; // the decomposed HE encrypted data of user's c_i
        //Ciphertext c_res;           // the HE encrypted results that will be sent to the Analyst

        unordered_map<string, PublicKey*> pkMap;
        unordered_map<string, RelinKeys*> rkMap;
        unordered_map<string, GaloisKeys*> gkMap;

        unordered_map< string, vector<Ciphertext> > encKeysMap;

};




