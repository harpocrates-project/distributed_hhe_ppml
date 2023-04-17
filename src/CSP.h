#pragma once

#include <unordered_map>
#include "Common.h"

using std::unordered_map;
using std::string;

class CSP
{
    public:

        CSP() 
        {
            context = get_seal_context(config::plain_mod, config::mod_degree, config::seclevel);
            keygen = new KeyGenerator(*context);
            he_eval = new Evaluator(*context);
            
            cout << "[CSP] Creating a new HE secret key from the context" << endl;
            he_sk = keygen->secret_key();

        }

        bool addPublicKey(string analystId, seal_byte* bytes, int size);
        bool addRelinKey(string analystId, seal_byte* bytes, int size);
        bool addGaloisKey(string analystId, seal_byte* bytes, int size);

        bool addEncWeights(string analystId, seal_byte* bytes, int size);
        bool addEncBias(string analystId, seal_byte* bytes, int size);

	bool addEncSymKeys(string analystId, vector<seal_byte*> bytes, vector<int> lengths);
        bool addEncSymData(string analystId, vector<uint64_t>);

        
        void decompose(string analystId);

        void evaluateModel(string analystId);

        int getEncryptedResultBytes(string analystId, seal_byte* &buffer);


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

        unordered_map<string, Ciphertext*> wcMap;
        unordered_map<string, Ciphertext*> bcMap;
  
	unordered_map< string, vector<Ciphertext> > encKeysMap;

        unordered_map< string, vector<uint64_t> > encDataMap;
        unordered_map< string, vector<Ciphertext> > heEncDataMap;
         
        unordered_map<string, Ciphertext> cResMap;
};
