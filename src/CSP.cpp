#include "CSP.h"

void CSP::decompose(string analystId)
{
    //cout << "[CSP] Analyst Id: " << analystId << endl;
    //cout << "[CSP] Encrpyted data size: " << encDataMap[analystId].size() << endl;
    //cout << "[CSP] Number of Symmetric keys: " << encKeysMap[analystId].size() << endl;

    cout << "[CSP] Making a PASTA_SEAL Worker Object based on the CSP HE sk and Analyst's HE pk (Analyst Id: " << analystId << ")" << endl;
    PASTA_3_MODIFIED_1::PASTA_SEAL CSPWorker(context, *pkMap[analystId], he_sk, *rkMap[analystId], *gkMap[analystId]);

    cout << "[CSP] Decompose: Turning the user's SKE encrypted data c_i into HE encryped c_prime" << endl;
    heEncDataMap[analystId] = CSPWorker.decomposition(encDataMap[analystId], encKeysMap[analystId], config::USE_BATCH);

    cout << "[CSP] Decompose completed" << endl;
}


void CSP::evaluateModel(string analystId)
{
    cout << "[CSP] Evaluating a linear transformation using c_prime, Analyst's encrypted weights and biases (Analyst Id: " << analystId << ")" << endl;

    Ciphertext c_res;
    packed_enc_multiply(heEncDataMap[analystId][0], *wcMap[analystId], c_res, *he_eval);
    packed_enc_addition(c_res, *bcMap[analystId], c_res, *he_eval);
 
    cResMap[analystId] = c_res;

    cout << "[CSP] Evaluation completed" << endl;
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

bool CSP::addEncWeights(string analystId, seal_byte* bytes, int size)
{
    cout << "[CSP] Adding Encrypted Weights (Analyst Id: " << analystId << ")" << endl;

    /*
    for (int i = 0; i < 10; i++) {
        std::cout << (int)bytes[i] << ' ';
    }
    cout << endl;
    */

    Ciphertext *w_c = new Ciphertext();
    w_c->load(*context, bytes, size);

    wcMap[analystId] = w_c;

    return true;
}

bool CSP::addEncBias(string analystId, seal_byte* bytes, int size)
{
    cout << "[CSP] Adding Encrypted Bias (Analyst Id: " << analystId << ")" << endl;

    /*
    for (int i = 0; i < 10; i++) {
        std::cout << (int)bytes[i] << ' ';
    }
    cout << endl;
    */

    Ciphertext *b_c = new Ciphertext();
    b_c->load(*context, bytes, size);

    bcMap[analystId] = b_c;

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


bool CSP::addEncSymData(string analystId, vector<uint64_t> values)
{
    cout << "[CSP] Adding Encrypted Symmetric Data (Analyst Id: " << analystId << ")" << endl;

    encDataMap[analystId] = values;
    return true;
}


int CSP::getEncryptedResultBytes(string analystId, seal_byte* &buffer)
{
    Ciphertext c_res = cResMap[analystId];

    int c_res_size = c_res.save_size();
    buffer = new seal_byte[c_res_size];
    c_res.save(buffer, c_res_size);

    cout << "[CSP] Serialised Encrypted Result for analyst (Analyst Id: " << analystId << ", size: " << c_res_size << ")" << endl;

    /*
    for (int i = 0; i < 10; i++) {
        std::cout << (int)buffer[i] << ' ';
    }
    cout << endl;
    */

    return c_res_size; 
}

