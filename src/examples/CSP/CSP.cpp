#include "CSP.h"

// setter
// keygen
void CSP::setKeyGenerator(){
    keygen = new KeyGenerator(*context);
}
// evaluator
void CSP::setEvaluator(){
    he_eval = new Evaluator(*context); 
}
// he_sk
void CSP::setCSPHeSecretKey(KeyGenerator* keygen){
    cout << "[CSP] Creating a new HE secret key from the context" << endl;
    he_sk = keygen->secret_key();
}

// getter
// keygen
KeyGenerator* CSP::getKeyGenerator(){
    return keygen;
} 
// he_enc
Evaluator* CSP::getEvaluator(){
    return he_eval;
} 
// he_sk
SecretKey CSP::getCSPHeSecretKey(){
    return he_sk;
}

void CSP::heInitialization(){
    // setter
    setKeyGenerator();
    setEvaluator();

    // getter
    keygen = getKeyGenerator();
    he_eval = getEvaluator();

    setCSPHeSecretKey(keygen);

    // print value
    // cout << "keygen: " << keygen << endl;
    // cout << "he_benc: " << he_benc << endl;

    // print addr
    // cout << "keygen: " << &keygen << endl;
    // cout << "he_benc: " << &he_benc << endl;
}


bool CSP::addPublicKey(string analystId, seal_byte* bytes, int size)
{
    cout << "[CSP] Adding public key (Analyst Id: " << analystId << ")" << endl;
    
    /*
    for (int i = 0; i < 10; i++) {
        std::cout << (int)bytes[i] << ' ';
    }
    cout << endl;
    */

    PublicKey *he_pk = new PublicKey();
    he_pk->load(*context, bytes, size);
    
    pkMap[analystId] = he_pk;

    return true;
}

bool CSP::addRelinKey(string analystId, seal_byte* bytes, int size)
{
    cout << "[CSP] Adding relin key (Analyst Id: " << analystId << ")" << endl;

    /*
    for (int i = 0; i < 10; i++) {
        std::cout << (int)bytes[i] << ' ';
    }
    cout << endl;
    */

    RelinKeys *he_rk = new RelinKeys();
    he_rk->load(*context, bytes, size);

    rkMap[analystId] = he_rk;

    return true;
}

bool CSP::addGaloisKey(string analystId, seal_byte* bytes, int size)
{
    cout << "[CSP] Adding galois key (Analyst Id: " << analystId << ")" << endl;

    /*
    for (int i = 0; i < 10; i++) {
        std::cout << (int)bytes[i] << ' ';
    }
    cout << endl;
    */

    GaloisKeys *he_gk = new GaloisKeys();
    he_gk->load(*context, bytes, size);

    gkMap[analystId] = he_gk;

    return true;
}

bool CSP::addEncSymKeys(string analystId, vector<seal_byte*> bytes, vector<int> lengths)
{
    cout << "[CSP] Adding Encrypted Symmetric Keys (Analyst Id: " << analystId << ")" << endl;

    vector<Ciphertext> keys;

    for (int i=0; i<bytes.size(); i++)
    {
        Ciphertext* key = new Ciphertext();
        key->load(*context, bytes[i], lengths[i]);
        keys.push_back(*key);
    }

    encKeysMap[analystId] = keys;

    return true;
}
