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
        /** 
        Create a HE key generator 
        */
        void setKeyGenerator(); // csp_keygen
        
        /**
        Create a HE evaluator
        */
        void setEvaluator(); // evaluator

        /**
        Create a HE Secret key
        */
        void setHESecretKey(KeyGenerator* csp_keygen); // csp_he_sk
    

        // getter
        /**
        Return the HE key generator
        */
        KeyGenerator* getKeyGenerator(); // csp_keygen

        /**
        Return the HE evaluator
        */
        Evaluator* getEvaluator(); // csp_he_eval

        /**
        Return the HE Secret key
        */
        SecretKey getHESecretKey(); // csp_he_sk

        /**
        Return the Analyst HE Public key
        @param[in] analystId The Analyst IP Addr
        */
        PublicKey getAnalystHEPublicKey(string analystId); // Analyst_he_pk
        
        /**
        Return the Analyst HE Relin keys
        @param[in] analystId The Analyst IP Addr
        */
        RelinKeys getAnalystHERelinKeys(string analystId); // Analyst_he_rk
        
        /**
        Return the Analyst HE Galois keys
        @param[in] analystId The Analyst IP Addr
        */
        GaloisKeys getAnalystHEGaloisKeys(string analystId); // Analyst_he_gk 
        
        /**
        Return the User encrypted symmetric key
        @param[in] analystId The Analyst IP Addr
        */
        vector<Ciphertext> getUserEncryptedSymmetricKey(string analystId); // Client_hhe_key
       
        /**
        Return the User encrypted data
        @param[in] analystId The Analyst IP Addr
        */       
        //vector<uint64_t> getUserEncryptedData(string analystId);  // vi_se
        
        /**
        Return the HE encrypted data
        @param[in] analystId The Analyst IP Addr
        */
        vector<Ciphertext> getHEEncryptedData(string analystId); // vi_he

        /**
        Return the encrypted result calculated by CSP via HHE decomposition and evaluation
        */
        int getEncryptedResultBytes(string analystId, seal_byte* &buffer);


        // functions
        /**
        Set up HE parameters
        */
        void hEInitialization();
        
        /**
        Add Analyst HE Public key on CSP 
        @param[in] analystId The Analyst IP Addr
        @param[in] bytes The key bytes
        @param[in] size The key length
        */
        bool addAnalystHEPublicKey(string analystId, seal_byte* bytes, int size);
        
        /**
        Add Analyst HE Relin keys on CSP 
        @param[in] analystId The Analyst IP Addr
        @param[in] bytes The key bytes
        @param[in] size The key length
        */
        bool addAnalystHERelinKeys(string analystId, seal_byte* bytes, int size); 
        
        /**
        Add Analyst HE Galois keys on CSP 
        @param[in] analystId The Analyst IP Addr
        @param[in] bytes The key bytes
        @param[in] size The key length
        */
        bool addAnalystHEGaloisKeys(string analystId, seal_byte* bytes, int size);

        /**
        Add CSP HE Relin keys
        @param[in] analystId The Analyst IP Addr
        @param[in] bytes The key bytes
        @param[in] size The key length
        */
        bool addHERelinKeys(string analystId, seal_byte* bytes, int size); 
        
        /**
        Add CSP HE Galois keys
        @param[in] analystId The Analyst IP Addr
        @param[in] bytes The key bytes
        @param[in] size The key length
        */
        bool addHEGaloisKeys(string analystId, seal_byte* bytes, int size);

        /**
        Add User encrypted symmetric key on CSP
        @param[in] analystId The Analyst IP Addr
        @param[in] bytes The key bytes
        @param[in] lengths The key length
        */
        bool addUserEncryptedSymmetricKey(string analystId, vector<seal_byte*> bytes, vector<int> lengths);
        
        /**
        Add User encrypted data on CSP
        @param[in] analystId The Analyst IP Addr
        @param[in] values The data values
        */
        bool addUserEncryptedData(string analystId, vector<uint64_t> values);
       
        /**
        Add Analyst NN model encrypted weights on CSP
        @param[in] analystId The Analyst IP Addr
        @param[in] bytes The encrypted weights bytes
        @param[in] size The encrypted weights size
        */
        bool addAnalystEncryptedWeights(string analystId, vector<seal_byte*> bytes, vector<int> size);

        /**
        HHE decomposition
        */
        void decompose(string analystId);

        /**
        HHE evaluation
        */
        void evaluateModel(string analystId);

        /**
        Helper function to print the first ten bytes of the seal_byte input
        */
        void print_seal_bytes(seal_byte* buffer);
        
        /**
        Helper function to print ciphertext
        */
        void print_Ciphertext(Ciphertext input);

        /**
        Helper function to print the ciphertext vector 
        */
        void print_vec_Ciphertext(vector<Ciphertext> input, size_t size);
        
    private:   
        shared_ptr<SEALContext> context;
        Evaluator* csp_he_eval;
        BatchEncoder* he_benc;

        KeyGenerator* csp_keygen;
        SecretKey csp_he_sk;

        //GaloisKeys csp_gk;
        //RelinKeys csp_rk;

        unordered_map<string, PublicKey*> analyst_he_pk_map;
        unordered_map<string, RelinKeys*> analyst_he_rk_map;
        unordered_map<string, GaloisKeys*> analyst_he_gk_map;
        unordered_map<string, RelinKeys*> csp_he_rk_map;
        unordered_map<string, GaloisKeys*> csp_he_gk_map;

        unordered_map<string, vector<Ciphertext>> enc_weights_map;  // Analyst's encrypted weights
        unordered_map<string, vector<Ciphertext>> enc_sym_key_map; // User's encrypted symmetric keys
        unordered_map<string, vector<uint64_t>> enc_data_map;      // User's encrypted data    
        unordered_map<string, vector<Ciphertext>> he_enc_data_map; // The HHE decomposition results. (vi_he)  

        unordered_map<string, Ciphertext> he_enc_data_processed_map; // HHE decomposition postprocessing on the HE encrypted input. (vi_he_processed)
        unordered_map<string, Ciphertext> he_enc_product_map; // The multiply of vi_he_processed. (encrypted_product)
        unordered_map<string, Ciphertext> he_sum_enc_product_map; // The results will be sent to Analyst. (sum of encrypted_product)
};




