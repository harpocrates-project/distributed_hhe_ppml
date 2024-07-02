#include "CSP.h"

// setter
/** 
Create a HE key generator 
*/
void BaseCSP::setKeyGenerator()
{
    csp_keygen = new KeyGenerator(*context);
}

/**
Create a HE evaluator
*/
void BaseCSP::setEvaluator()
{
    csp_he_eval = new Evaluator(*context); 
}

/**
Create a HE Secret key
*/
void BaseCSP::setHESecretKey(KeyGenerator* csp_keygen)
{
    cout << "[CSP] Creating a new HE secret key from the context" << endl;
    csp_he_sk = csp_keygen->secret_key();
}

// getter
/**
Return the HE key generator
*/
KeyGenerator* BaseCSP::getKeyGenerator()
{
    return csp_keygen;
} 

/**
Return the HE evaluator
*/
Evaluator* BaseCSP::getEvaluator()
{
    return csp_he_eval;
} 

/**
Return the HE Secret key
*/
SecretKey BaseCSP::getHESecretKey()
{
    return csp_he_sk;
}

/**
Return the Analyst HE Public key
*/
PublicKey BaseCSP::getAnalystHEPublicKey(string analystId)
{
    return *analyst_he_pk_map[analystId];
}

/**
Return the Analyst HE Relin keys
*/
RelinKeys BaseCSP::getAnalystHERelinKeys(string analystId)
{
    return *analyst_he_rk_map[analystId];
}

/**
Return the Analyst HE Galois keys
*/ 
GaloisKeys BaseCSP::getAnalystHEGaloisKeys(string analystId)
{
    return *analyst_he_gk_map[analystId];
}

/**
Return the User encrypted symmetric key
*/
vector<Ciphertext> BaseCSP::getUserEncryptedSymmetricKey(string analystId)
{
    return enc_sym_key_map[analystId];
}

/**
Return the User encrypted data
*/
// vector<uint64_t> BaseCSP::getUserEncryptedData(string analystId)
// {
//     cout << "[CSP] Obtaining User's encrypted data (Analyst Id: " << analystId << ")" << endl;
//     return enc_data_map[analystId];  
// } 

/**
Return the HE encrypted data
*/
vector<Ciphertext> BaseCSP::getHEEncryptedData(string analystId)
{
    return he_enc_data_map[analystId];   
}

/**
Return the encrypted result calculated by CSP via HHE decomposition and evaluation
*/
int BaseCSP::getEncryptedResultBytes(string analystId, seal_byte* &buffer)
{
    Ciphertext encrypted_sum_vec = he_sum_enc_product_map[analystId];

    int encrypted_sum_vec_size = encrypted_sum_vec.save_size();
    buffer = new seal_byte[encrypted_sum_vec_size];
    encrypted_sum_vec.save(buffer, encrypted_sum_vec_size);

    cout << "[CSP] Serialised encrypted result for Analyst (AnalystId: " << analystId << ", size: " << encrypted_sum_vec_size << ")" << endl;
    print_seal_bytes(buffer);
    
    return encrypted_sum_vec_size; 
}

// functions
/*
Helper function to print the first ten bytes of the seal_byte input.
*/
void BaseCSP::print_seal_bytes(seal_byte* buffer)
{
    for (int i = 0; i < 10; i++)
    {
        cout << (int)buffer[i] << ' ';
    }
    cout << "... ..." << endl;
}

/**
Helper function to print ciphertext
*/
void BaseCSP::print_Ciphertext(Ciphertext input)
{
        seal_byte* buffer = nullptr;

        int input_size = input.save_size();
        buffer = new seal_byte[input_size];
        input.save(buffer, input_size); 
        print_seal_bytes(buffer);
}

/**
Helper function to print the ciphertext vector 
*/
void BaseCSP::print_vec_Ciphertext(vector<Ciphertext> input, size_t size)
{
        for (int i = 0; i < size; i++)
        {
            print_Ciphertext(input[i]);
            cout << "input_size: " << input[i].save_size() << endl;
        }
}

/**
Set up HE parameters
*/
void BaseCSP::hEInitialization(){
    // setter
    setKeyGenerator();
    setEvaluator();
    
    // getter
    csp_keygen = getKeyGenerator();
    csp_he_eval = getEvaluator();

    setHESecretKey(csp_keygen);
}

/**
HHE decomposition
*/
void BaseCSP::decompose(string analystId)
{
    cout << "[CSP] Making a PASTA_SEAL HHE object based on the CSP's HE sk and Analyst's HE pk, rk, gk (Analyst Id: " << analystId << ")" << endl;
    pasta::PASTA_SEAL HHE(context, 
                          getAnalystHEPublicKey(analystId), 
                          getHESecretKey(), 
                          getAnalystHERelinKeys(analystId), 
                          getAnalystHEGaloisKeys(analystId));

    cout << "[CSP] Decomposition: CSP does HHE decomposition to turn User's symmetric input into HE input" << endl;
    he_enc_data_map[analystId] = HHE.decomposition(enc_data_map[analystId],
                                                getUserEncryptedSymmetricKey(analystId), 
                                                config::USE_BATCH);

    print_vec_Ciphertext(he_enc_data_map[analystId], he_enc_data_map[analystId].size());

    cout << "[CSP] Decomposition completed" << endl;

    cout << "[CSP] Executing HHE decomposition postprocessing on the HE encrypted input" << endl;
    int inputLen = 300;
    // size_t num_block = inputLen / HHE.get_plain_size();
    size_t rem = inputLen % HHE.get_plain_size();
    // if (rem)
    // { 
    //     num_block++;
    // }
    // cout << "There are " << heEncDataMap[analystId].size() << " decomposed HE ciphertexts\n";
    // cout << "HHE cipher one block's plain size " << HHE.get_plain_size() << endl;
    // cout << "num_block = " << num_block << endl;
    // cout << "rem = " << rem << endl;
    // cout << "Preparing necessary things to do postprocessing (creating new Galois key, masking, flattening)" << endl;
    // vector<int> flatten_gks;
    // for (int i = 1; i < num_block; i++)
    // {
    //     flatten_gks.push_back(-(int)(i * HHE.get_plain_size()));
    // }

  
    // bool use_bsgs = false;
    // seal::BatchEncoder analyst_he_benc111(*context);
    // // gk_indices = pastahelper::add_gk_indices(use_bsgs, *he_benc);
    // vector<int> gk_indices = pastahelper::add_gk_indices(use_bsgs, analyst_he_benc111);
    // utils::print_vec(gk_indices, gk_indices.size(), "gk_indices");
    // utils::print_vec(flatten_gks, flatten_gks.size(), "flatten_gks");

    // vector<int> csp_gk_indices = pastahelper::add_some_gk_indices(gk_indices, flatten_gks);
    // utils::print_vec(csp_gk_indices, csp_gk_indices.size(), "csp_gk_indices");

    // keygen->create_galois_keys(csp_gk_indices, csp_gk);
    // keygen->create_relin_keys(csp_rk);
    if (rem != 0)
    {
        vector<uint64_t> mask(rem, 1);
        HHE.mask(he_enc_data_map[analystId].back(), mask);
    }

    HHE.flatten(he_enc_data_map[analystId], 
                he_enc_data_processed_map[analystId], 
                *csp_he_gk_map[analystId]);  // vi_he_processed = hhe_decomposition = C_prime

    cout << "The HHE decomposition postprocessing result is " << endl; // vi_he_processed
    print_Ciphertext(he_enc_data_processed_map[analystId]);
} 

/**
HHE evaluation
*/
void BaseCSP::evaluateModel(string analystId)
{
        cout << "[CSP] Evaluating the HE weights on the decomposed HE data" << endl;
        sealhelper::packed_enc_multiply(he_enc_data_processed_map[analystId], 
                                        enc_weights_map[analystId][0],
                                        he_enc_product_map[analystId], 
                                        *csp_he_eval); 

        cout << "encrypted_product size before relinearization = " << he_enc_product_map[analystId].size() << endl;
        csp_he_eval->relinearize_inplace(he_enc_product_map[analystId], *csp_he_rk_map[analystId]);
        cout << "encrypted_product size after relinearization = " << he_enc_product_map[analystId].size() << endl;

        // Do encrypted sum on the resulting product vector
        cout << "[CSP] Executing encrypted sum on the encrypted vector" << endl;
        int inputLen = 300;

        sealhelper::encrypted_vec_sum(he_enc_product_map[analystId], 
                                      he_sum_enc_product_map[analystId], 
                                      *csp_he_eval, 
                                      *analyst_he_gk_map[analystId], 
                                      inputLen);
        cout << "[CSP] Evaluation completed" << endl;
} 

/**
Add Analyst HE Public key on CSP
*/
bool BaseCSP::addAnalystHEPublicKey(string analystId, seal_byte* bytes, int size)
{
    cout << "[CSP] Adding Analyst HE Public key (AnalystId: " << analystId << ") and (size=" << size << ")" << endl;
    print_seal_bytes(bytes);

    PublicKey *analyst_he_pk = new PublicKey();
    analyst_he_pk->load(*context, bytes, size);
    
    analyst_he_pk_map[analystId] = analyst_he_pk;

    return true;
}

/**
Add Analyst HE Galois keys on CSP
*/
bool BaseCSP::addAnalystHERelinKeys(string analystId, seal_byte* bytes, int size)
{
    cout << "[CSP] Adding Analyst HE Relin keys (AnalystId: " << analystId << ") and (size=" << size << ")" << endl;
    print_seal_bytes(bytes);
    
    RelinKeys *analyst_he_rk = new RelinKeys();
    analyst_he_rk->load(*context, bytes, size);

    analyst_he_rk_map[analystId] = analyst_he_rk;

    return true;
}

/**
Add CSP HE Relin keys
*/
bool BaseCSP::addHERelinKeys(string analystId, seal_byte* bytes, int size)
{
    cout << "[CSP] Adding CSP Relin keys (AnalystId: " << analystId << ") and (size=" << size << ")" << endl;
    print_seal_bytes(bytes);
    
    RelinKeys *csp_he_rk = new RelinKeys();
    csp_he_rk->load(*context, bytes, size);

    csp_he_rk_map[analystId] = csp_he_rk;

    return true;
}

/**
Add Analyst HE Galois keys on CSP
*/
bool BaseCSP::addAnalystHEGaloisKeys(string analystId, seal_byte* bytes, int size)
{
    cout << "[CSP] Adding Analyst Galois keys (AnalystId: " << analystId << ") and (size=" << size << ")"  << endl;
    print_seal_bytes(bytes); 

    GaloisKeys *analyst_he_gk = new GaloisKeys();
    analyst_he_gk->load(*context, bytes, size);

    analyst_he_gk_map[analystId] = analyst_he_gk;

    return true;
}

/**
Add CSP HE Galois keys
*/
bool BaseCSP::addHEGaloisKeys(string analystId, seal_byte* bytes, int size)
{
    cout << "[CSP] Adding CSP Galois keys (AnalystId: " << analystId << ") and (size=" << size << ")"  << endl;
    print_seal_bytes(bytes);
    
    GaloisKeys *csp_he_gk = new GaloisKeys();
    csp_he_gk->load(*context, bytes, size);

    csp_he_gk_map[analystId] = csp_he_gk;

    return true;
}

/**
Add User encrypted symmetric key on CSP
*/
bool BaseCSP::addUserEncryptedSymmetricKey(string analystId, vector<seal_byte*> bytes, vector<int> lengths)
{
    cout << "[CSP] Adding User encrypted symmetric key (AnalystId: " << analystId << ")" << endl;

    vector<Ciphertext> keys;

    for (int i=0; i<bytes.size(); i++)
    {
        Ciphertext* key = new Ciphertext();
        key->load(*context, bytes[i], lengths[i]);
        keys.push_back(*key);
    }

    enc_sym_key_map[analystId] = keys;

    return true;
}

/**
Add User encrypted data on CSP
*/
bool BaseCSP::addUserEncryptedData(string analystId, vector<uint64_t> values)
{
    cout << "[CSP] Adding User encrypted data (AnalystId: " << analystId << ")" << endl;

    enc_data_map[analystId] = values;
    return true;
}

/**
Add Analyst NN model encrypted weights on CSP
*/
bool BaseCSP::addAnalystEncryptedWeights(string analystId, vector<seal_byte*> bytes, vector<int> size)
{
    cout << "[CSP] Adding ML model encrypted weights (AnalystId: " << analystId << ")" << endl;

    vector<Ciphertext> weights;

    for (int i=0; i<bytes.size(); i++)
    {
        Ciphertext* weight = new Ciphertext();
        weight->load(*context, bytes[i], size[i]);
        weights.push_back(*weight);
    }

    enc_weights_map[analystId] = weights;

    return true;
}



