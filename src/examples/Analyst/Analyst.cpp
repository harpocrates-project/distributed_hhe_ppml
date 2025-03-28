#include "Analyst.h"

// setter
/**
Set up a data set name for NN calculation
*/
void BaseAnalyst::setDataSet(string data_set){
    dataset = data_set;
}

/** 
Create a HE key generator 
*/
void BaseAnalyst::setKeyGenerator()
{
    analyst_keygen = new KeyGenerator(*context);
}

/**
Create a batch encoder
*/
void BaseAnalyst::setBatchEncoder()
{
    analyst_he_benc = new BatchEncoder(*context);
}

/** 
Create a HE Secret key
*/
void BaseAnalyst::setHESecretKey(KeyGenerator* analyst_keygen)
{
    analyst_he_sk = analyst_keygen->secret_key();
}

/**
Create a HE Public key
*/
void BaseAnalyst::setHEPublicKey(KeyGenerator* analyst_keygen)
{
    analyst_keygen->create_public_key(analyst_he_pk); 
}   

/** 
Create HE Relin keys
*/
void BaseAnalyst::setHERelinKeys(KeyGenerator* analyst_keygen)
{
    analyst_keygen->create_relin_keys(analyst_he_rk);
}

/** 
Create HE Relin keys for CSP
*/
void BaseAnalyst::setCSPHERelinKeys(KeyGenerator* analyst_keygen)
{
    analyst_keygen->create_relin_keys(csp_he_rk);
}

/** 
Create HE Galois keys
*/
void BaseAnalyst::setHEGaloisKeys(KeyGenerator* analyst_keygen)
{
    analyst_keygen->create_galois_keys(analyst_he_gk);  
}

/** 
Create HE Galois keys for CSP
*/
void BaseAnalyst::setCSPHEGaloisKeys(BatchEncoder* analyst_he_benc, KeyGenerator* analyst_keygen)
{
    int inputLen = 300;
    // size_t num_block = inputLen / HHE.get_plain_size();
    // size_t rem = inputLen % HHE.get_plain_size();
    size_t num_block = inputLen / 128;
    size_t rem = inputLen % 128;
    if (rem)
    { 
        num_block++;
    }
    
    vector<int> flatten_gks;
    for (int i = 1; i < num_block; i++)
    {
        //flatten_gks.push_back(-(int)(i * HHE.get_plain_size()));
        flatten_gks.push_back(-(int)(i * 128));
    }

    bool use_bsgs = false;
    vector<int> gk_indices = add_gk_indices(use_bsgs, *analyst_he_benc);
    vector<int> csp_gk_indices = add_some_gk_indices(gk_indices, flatten_gks);
    
    analyst_keygen->create_galois_keys(csp_gk_indices, csp_he_gk); 
}

/**
Create a HE encryptor
*/
void BaseAnalyst::setEncryptor()
{
    analyst_he_enc = new Encryptor(*context, analyst_he_pk); 
}

/** 
Create a HE evaluator
*/
void BaseAnalyst::setEvaluator(){
    analyst_he_eval = new Evaluator(*context); 
}

/** 
Create a HE decryptor
*/
void BaseAnalyst::setDecryptor(){
    analyst_he_dec = new Decryptor(*context, analyst_he_sk);
}

// getter
/**
Return a data set name for NN calculation
*/
string BaseAnalyst::getDataSet(){
    return dataset;
}

/**
Return a HE key generator 
*/
KeyGenerator* BaseAnalyst::getKeyGenerator()
{
    return analyst_keygen;
} 

/** 
 Return a batch encoder
*/
BatchEncoder* BaseAnalyst::getBatchEncoder()
{
    return analyst_he_benc;
}

/** 
Return a HE Secret key
*/
SecretKey BaseAnalyst::getHESecretKey()
{
    return analyst_he_sk;
}

/** 
Return a HE Public key
*/
PublicKey BaseAnalyst::getHEPublicKey()
{
    return analyst_he_pk;
}
/** 
Returns a HE Relin keys
*/
RelinKeys BaseAnalyst::getHERelinKeys()
{
    return analyst_he_rk;
}

/** 
Return a HE Galois keys
*/
GaloisKeys BaseAnalyst::getHEGaloisKeys()
{
    return analyst_he_gk;
}

/** 
Return a HE encryptor
*/
Encryptor* BaseAnalyst::getEncryptor()
{
    return analyst_he_enc;
} 

/** 
Return a HE evaluator
*/ 
Evaluator* BaseAnalyst::getEvaluator()
{
    return analyst_he_eval;
} 

/**
Return a HE decryptor
*/
Decryptor* BaseAnalyst::getDecryptor()
{
    return analyst_he_dec;
} 

/**
Return the seal context
*/
shared_ptr<SEALContext> BaseAnalyst::getContext()
{ 
    return context; 
}

/*
Helper function to print the first ten bytes of the seal_byte input.
*/
void BaseAnalyst::print_seal_bytes(seal_byte* buffer)
{
    for (int i = 0; i < 10; i++)
    {
        cout << (int)buffer[i] << ' ';
    }
    cout << "... ..." << endl;
}

/**
Set up HE parameters
*/
void BaseAnalyst::hEInitialization()
{
    // setter
    setKeyGenerator();
    setBatchEncoder();

    // getter
    analyst_keygen = getKeyGenerator();
    analyst_he_benc = getBatchEncoder();
}

/**
Create HE keys
*/
void BaseAnalyst::generateHEKeys()
{
    cout << "Analyst constructs the HE context" << endl;
    print_parameters(*context);

    cout << "[Analyst] Creating HE keys, batch encoder, encryptor and evaluator from the context" << endl;
    
    hEInitialization();
    setHESecretKey(analyst_keygen); // analyst_he_sk
    setHEPublicKey(analyst_keygen); // analyst_he_pk
    setHERelinKeys(analyst_keygen); // analyst_he_rk
    setHEGaloisKeys(analyst_keygen); // analyst_he_gk

    setCSPHERelinKeys(analyst_keygen); // csp_he_rk
    setCSPHEGaloisKeys(analyst_he_benc, analyst_keygen); // csp_he_gk
}

/**
Return the byte size for HE Public key
*/
int BaseAnalyst::getPublicKeyBytes(seal_byte* &buffer)
{
    int analyst_he_pk_size = analyst_he_pk.save_size();
    buffer = new seal_byte[analyst_he_pk_size];
    analyst_he_pk.save(buffer, analyst_he_pk_size); 

    cout << "[Analyst] Serialising Public key (size=" << analyst_he_pk_size << ")" << endl;
    print_seal_bytes(buffer);
    
    return analyst_he_pk_size;
}

/**
Return the byte size for HE Relin keys
*/
int BaseAnalyst::getRelinKeysBytes(seal_byte* &buffer)
{
    int analyst_he_rk_size = analyst_he_rk.save_size();
    buffer = new seal_byte[analyst_he_rk_size];
    analyst_he_rk.save(buffer, analyst_he_rk_size);

    cout << "[Analyst] Serialising Relin key (size=" << analyst_he_rk_size << ")" << endl;
    print_seal_bytes(buffer);
    
    return analyst_he_rk_size;
}

/**
Return the byte size for HE Relin keys of CSP
*/
int BaseAnalyst::getCSPRelinKeysBytes(seal_byte* &buffer)
{
    int csp_he_rk_size = csp_he_rk.save_size();
    buffer = new seal_byte[csp_he_rk_size];
    csp_he_rk.save(buffer, csp_he_rk_size);

    cout << "[Analyst] Serialising CSP Relin key (size=" << csp_he_rk_size << ")" << endl;
    print_seal_bytes(buffer);
    
    return csp_he_rk_size;
}

/**
Return the byte size for HE Galois keys
*/
int BaseAnalyst::getGaloisKeysBytes(seal_byte* &buffer)
{
    int analyst_he_gk_size = analyst_he_gk.save_size();
    buffer = new seal_byte[analyst_he_gk_size];
    analyst_he_gk.save(buffer, analyst_he_gk_size);

    cout << "[Analyst] Serialising Galois key (size=" << analyst_he_gk_size << ")" << endl;
    print_seal_bytes(buffer);

    return analyst_he_gk_size;
}

/**
Return the byte size for HE Galois keys of CSP
*/
int BaseAnalyst::getCSPGaloisKeysBytes(seal_byte* &buffer)
{
    int csp_he_gk_size = csp_he_gk.save_size();
    buffer = new seal_byte[csp_he_gk_size];
    csp_he_gk.save(buffer, csp_he_gk_size);

    cout << "[Analyst] Serialising CSP Galois key (size=" << csp_he_gk_size << ")" << endl;
    print_seal_bytes(buffer);
    
    return csp_he_gk_size;
}

/**
Return the result for HE encryption of ML weights
*/
vector<Ciphertext> BaseAnalyst::getEncryptedWeights() { 
    return enc_weights_t; 
}

/**
Return the byte size for encrypted ML weights
*/
int BaseAnalyst::getEncryptedWeightsBytes(seal_byte* &buffer, int index)
{
    Ciphertext enc_weights = enc_weights_t[index];
    int enc_weights_t_size = enc_weights.save_size();
    buffer = new seal_byte[enc_weights_t_size];
    enc_weights.save(buffer, enc_weights_t_size);

    cout << "[Analyst] Serialising encrypted weights (size=" << enc_weights_t_size << ")" << endl;
    print_seal_bytes(buffer);
    
    return enc_weights_t_size;
}

/**
 Decrypt the Ciphertext from CSP and obtains the plaintext result.
*/
void BaseAnalyst::decryptData(seal_byte* bytes, int size)
{
    cout << "[Analyst] Decrypting the HE encrypted results (size: " << size << ") received from the CSP" << endl;
    print_seal_bytes(bytes);

    Ciphertext* encrypted_sum_vec = new Ciphertext();
    encrypted_sum_vec->load(*context, bytes, size);

    decrypted_result = decrypting(*encrypted_sum_vec, 
                                  getHESecretKey(), 
                                  *getBatchEncoder(), 
                                  *getContext(), 
                                  inputLen);

    utils::print_vec(decrypted_result, decrypted_result.size(), "[Analyst] decrypted result");

    matrix::vector vo(1);
    vo[0] = decrypted_result[inputLen - 1];

    //cout << "Plaintext FC layer output: " << vo_p[0] << endl;
    cout << "Decrypted HHE FC layer output: " << vo[0] << endl;

    cout << "Analyst applies the sigmoid to get final prediction" << endl;
    int64_t hhe_pred = utils::int_sigmoid(vo[0]);
    cout << "HHE prediction = " << hhe_pred << " | ";
    //cout << "plain prediction = " << plain_pred << " | ";
    //cout << "ground-truth prediction = " << gt_out << endl;
    
    cout << "\n---------------------- Done ----------------------" << endl;
}

/**
The implementation of the pure virtual function, which will be used for HHE PocketNN 1FC model encryption. 
*/
void Analyst_hhe_pktnn_1fc::NNModelEncryption(string dataset)
{ 
    // check if the lowercase of the `dataset` string is either "spo2" or "mnist"
    string lowerStr = dataset;
    transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(), ::tolower);
    if (lowerStr != "spo2" && lowerStr != "ecg")
    {
            throw runtime_error("Dataset must be either SpO2 or ECG");
    }   
    inputLen = 0;
    if (lowerStr == "spo2")
    {
        inputLen = 300;
    }
    if (lowerStr == "ecg")
    {
        inputLen = 128;
    }
    
    cout << "[Analyst] Loading the pretrained weights" << endl;
    matrix::matrix weights;
    if (config::debugging)
    {
        weights = matrix::read_from_csv("../" + config::save_weight_path);
    } 
    else 
    {
        weights = matrix::read_from_csv(config::save_weight_path);
    }
    cout << "Reading weights from " << config::save_weight_path << endl;
    matrix::print_matrix_shape(weights);
    matrix::print_matrix_stats(weights);
    // matrix::print_matrix(weights);
    cout << "Transposed weights: ";
    matrix::matrix weights_t = matrix::transpose(weights);
    matrix::print_matrix_shape(weights_t);
    matrix::print_matrix(weights_t);

    // bias (all 0s)
    cout << "Ignoring Bias" << endl;

    cout << "[Analyst] Encrypting the weights using HE" << endl;
    enc_weights_t = sealhelper::encrypt_weight_mat(weights_t,
                                                   getHEPublicKey(),
                                                   *getBatchEncoder(),
                                                   *getEncryptor());

    cout << "(Check) [Analyst] Decrypting the encrypted weights" << endl;
    matrix::matrix dec_weights_t = sealhelper::decrypt_weight_mat(enc_weights_t,
                                                                  *getBatchEncoder(),
                                                                  *getDecryptor(),
                                                                  inputLen);
    cout << "Decrypted Weights: ";
    matrix::print_matrix_shape(dec_weights_t);
    matrix::print_matrix(dec_weights_t);
}

