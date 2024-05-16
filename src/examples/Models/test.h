#include "../../Common.h"

class BaseModel {
    public:
        BaseModel(){
		    context = get_seal_context(config::plain_mod, config::mod_degree, config::seclevel);	
            he_benc = new BatchEncoder(*context);
            keygen = new KeyGenerator(*context);
        }

        void test_ini();

        BatchEncoder* getBatchEncoder(); // he_benc
        SecretKey getAnalystHeSecretKey(); // he_sk
        PublicKey getAnalystHePublicKey(); // he_pk
        Encryptor* getEncryptor(); // he_enc
        Decryptor* getDecryptor(); // he_dec

        // pure virtual function
        virtual void func(PublicKey he_pk,BatchEncoder* he_benc,Encryptor* he_enc,Decryptor* he_dec) = 0;
        // virtual void func(PublicKey he_pk,BatchEncoder* he_benc,Encryptor* he_enc,Decryptor* he_dec) = 0;
    
    
    private:
        shared_ptr<SEALContext> context;

        PublicKey he_pk;
        SecretKey he_sk;

        KeyGenerator* keygen;
        BatchEncoder* he_benc;

        Encryptor* he_enc;
        Decryptor* he_dec;

};



class hhe_pktnn_1fc : public BaseModel {
    public:
        // implementation of the pure virtual function
        void func(PublicKey he_pk,BatchEncoder* he_benc,Encryptor* he_enc,Decryptor* he_dec);
};



