#pragma once

#include "../../Common.h"

class User
{
    public:
        User()
        {
            context = get_seal_context(config::plain_mod, config::mod_degree, config::seclevel);
            he_benc = new BatchEncoder(*context);
        }
        
        //setter
        /**
        Create a symmetric key
        */
        void setSymmetricKey(); // client_sym_key

        /**
        Set up a data set name for NN calculation
        */
        void setDataSet(string data_set); // dataset name
        

        // getter
        /**
        Return the symmetric key
        */
        vector<uint64_t> getSymmetricKey(); // client_sym_key
        
        /**
        Return the datas set name for NN calculation
        */
        string getDataSet();

        /**
        Return the encrypted symmetric key
        */
        vector<Ciphertext> getEncryptedSymmetricKey();
        
        /**
        Return the encrypted data
        */
        vector <vector<uint64_t>> getEncryptedData();
        
        /**
        Return the byte size for encrypted symmetric key
        */
        int getEncryptedSymmetricKeyBytes(seal_byte* &buffer, int index);


        // functions
        /**
        Load data and label for NN calculation
        */
        void loadDataAndLabel(string dataSet);
       
        /**
        Encrypt the plaintext data
        @param[in] client_sym_key The User symmetric key
        */
        void encryptData(vector<uint64_t> client_sym_key); // data encryption
        
        /**
        Encrypt the plaintext symmetric key
        @param[in] client_sym_key The User symmetric key
        @param[in] analyst_he_pk_bytes The Analyst HE Public key
        @param[in] size The size for Analyst HE Public key
        */
        void encryptSymmetricKey(vector<uint64_t> client_sym_key, seal_byte* analyst_he_pk_bytes, int size); // user's symmetric key encryption
        
        /** 
        Helper function to print the first ten bytes of the seal_byte input
        */
        void print_seal_bytes(seal_byte* buffer);
       
        /**
        Helper function to print the ciphertext vector
        */
        void print_vec_Ciphertext(vector<Ciphertext> input, size_t size);
    
        // void computingCheck();

    private:
        shared_ptr<SEALContext> context;
        BatchEncoder* he_benc;

        matrix::matrix data;    
        matrix::matrix labels; 
        matrix::vector vi; // plaintext data
        vector<uint64_t> vi_se; // symmetric encrypted vi
        vector <vector<uint64_t>> array; // the vector of vi_se
        vector<uint64_t> client_sym_key; // User's symmetric key
        vector<Ciphertext> client_hhe_key; // User's encrypted symmetric key (c_k)

        string dataSet;
};