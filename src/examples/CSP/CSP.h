#pragma once
#include <unordered_map>

#include "../../Common.h"


class BaseCSP
{
    public:

        BaseCSP() 
        {
            context = get_seal_context(config::plain_mod, config::mod_degree, config::seclevel);
            he_benc = new BatchEncoder(*context);
        }

        // setter
        void setKeyGenerator(); // keygen
        void setEvaluator(); // evaluator
        void setCSPHeSecretKey(KeyGenerator* keygen); // he_sk
    
        // getter
        KeyGenerator* getKeyGenerator(); // keygen
        Evaluator* getEvaluator(); // he_eval
        SecretKey getCSPHeSecretKey(); // he_sk
        PublicKey getAnalystHePublicKey(string analystId); // Analyst_he_pk
        RelinKeys getAnalystHeRelinKeys(string analystId); // Analyst_he_rk
        GaloisKeys getAnalystHeGaloisKeys(string analystId); // Analyst_he_gk 
        vector<Ciphertext> getUserHHEKey(string analystId); // Client_hhe_key
        // vector<uint64_t> getUserEncData(string analystId);  // vi_se
        vector<Ciphertext> getHeEncData(string analystId); // vi_he
      

        // functions
        void heInitialization();
        

        bool addPublicKey(string analystId, seal_byte* bytes, int size);
        bool addRelinKey(string analystId, seal_byte* bytes, int size);
        bool addGaloisKey(string analystId, seal_byte* bytes, int size);
        bool addSecretKey(string analystId, seal_byte* bytes, int size);
        bool addBatchEncoder(string analystId, seal_byte* bytes, int size);

        bool addEncSymKeys(string analystId, vector<seal_byte*> bytes, vector<int> lengths);
        bool addEncSymData(string analystId, vector<uint64_t>);
        bool addEncWeights(string analystId, vector<seal_byte*> bytes, vector<int> size);

        void decompose(string analystId);
        void evaluateModel(string analystId);

        void print_vec_Ciphertext(std::vector<seal::Ciphertext> input, size_t size);
        void print_Ciphertext(seal::Ciphertext input);
    
    private:
    
        shared_ptr<SEALContext> context;
        Evaluator* he_eval;
        BatchEncoder* he_benc;

        KeyGenerator* keygen;
        SecretKey he_sk;

        vector<int> csp_gk_indices;
        vector<int> gk_indices; 
        GaloisKeys csp_gk;
        RelinKeys csp_rk;

        //vector<Ciphertext> c_prime; // the decomposed HE encrypted data of user's c_i
        //Ciphertext c_res;           // the HE encrypted results that will be sent to the Analyst

        // Ciphertext vi_he_processed;   // HHE decomposition postprocessing on the HE encrypted input (vi_he)
        Ciphertext encrypted_product; // 
        Ciphertext encrypted_sum_vec; // sum of encrypted_product

        unordered_map<string, PublicKey*> pkMap;
        unordered_map<string, RelinKeys*> rkMap;
        unordered_map<string, GaloisKeys*> gkMap;
        unordered_map<string, SecretKey*> AnalystSkMap;

        unordered_map<string, vector<Ciphertext> > wcMap;  // Analyst's encrypted weights

        unordered_map<string, vector<Ciphertext> > encKeysMap; // User's encrypted symmetric keys
        unordered_map<string, vector<uint64_t> > encDataMap;   // User's encrypted data    
        unordered_map< string, vector<Ciphertext> > heEncDataMap; // vi_he        
};




