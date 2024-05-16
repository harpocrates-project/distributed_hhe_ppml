#include "Analyst.h"


// setter
// keygen
void Analyst::setKeyGenerator(){
    keygen = new KeyGenerator(*context);
}
// he_benc
void Analyst::setBatchEncoder(){
    he_benc = new BatchEncoder(*context);
}
// he_sk
void Analyst::setAnalystHeSecretKey(KeyGenerator* keygen){
    he_sk = keygen->secret_key();
}
// he_pk
void Analyst::setAnalystHePublicKey(KeyGenerator* keygen){
    keygen->create_public_key(he_pk); // HE_pk
}   
// he_rk
void Analyst::setAnalystHeRelinKeys(KeyGenerator* keygen){
    keygen->create_relin_keys(he_rk);
}
// he_gk
void Analyst::setAnalystHeGaloisKeys(BatchEncoder* he_benc, KeyGenerator* keygen){
    bool use_bsgs = false;
    vector<int> gk_indices = add_gk_indices(use_bsgs, *he_benc);
    keygen->create_galois_keys(gk_indices, he_gk);  // HE_gk
}
// encryptor
void Analyst::setEncryptor(){
    he_enc = new Encryptor(*context, he_pk); 
}
// evaluator
void Analyst::setEvaluator(){
    he_eval = new Evaluator(*context); 
}
// decryptor
void Analyst::setDecryptor(){
    he_dec = new Decryptor(*context, he_sk);
}

// getter
// keygen
KeyGenerator* Analyst::getKeyGenerator(){
    return keygen;
} 
// he_benc
BatchEncoder* Analyst::getBatchEncoder(){
    return he_benc;
}
// he_sk
SecretKey Analyst::getAnalystHeSecretKey(){
    return he_sk;
}
// he_pk
PublicKey Analyst::getAnalystHePublicKey(){
    return he_pk;
}
// he_rk
RelinKeys Analyst::getAnalystHeRelinKeys(){
    return he_rk;
}
// he_gk
GaloisKeys Analyst::getAnalystHeGaloisKeys(){
    return he_gk;
}
// he_enc
Encryptor* Analyst::getEncryptor(){
    return he_enc;
} 
// he_enc
Evaluator* Analyst::getEvaluator(){
    return he_eval;
} 
// he_dec
Decryptor* Analyst::getDecryptor(){
    return he_dec;
} 
// context
shared_ptr<SEALContext> Analyst::getContext(){ 
    return context; 
}




void Analyst::heInitialization(){
    // setter
    setKeyGenerator();
    setBatchEncoder();

    // getter
    keygen = getKeyGenerator();
    he_benc = getBatchEncoder();

    // print value
    // cout << "keygen: " << keygen << endl;
    // cout << "he_benc: " << he_benc << endl;

    // print addr
    // cout << "keygen: " << &keygen << endl;
    // cout << "he_benc: " << &he_benc << endl;
}


void Analyst::generateHEKeys(){
    print_parameters(*context);

    cout << "[Analyst] Creating HE keys, batch encoder, encryptor and evaluator from the context" << endl;
    
    heInitialization();
    setAnalystHeSecretKey(keygen); // he_sk
    setAnalystHePublicKey(keygen); // he_pk
    setAnalystHeRelinKeys(keygen); // he_rk
    setAnalystHeGaloisKeys(he_benc, keygen); // he_gk

    // he_enc = new Encryptor(*context, he_pk);   // HE_encryptor
}



int Analyst::getPublicKeyBytes(seal_byte* &buffer)
{
    int he_pk_size = he_pk.save_size();
    buffer = new seal_byte[he_pk_size];
    he_pk.save(buffer, he_pk_size); // write the he_pk to the buffer

    cout << "[Analyst] Serialising Public Key (size=" << he_pk_size << ")" << endl;

    for (int i = 0; i < 10; i++) {
        cout << (int)buffer[i] << ' ';
    }
    cout << endl;
    
    return he_pk_size;
}