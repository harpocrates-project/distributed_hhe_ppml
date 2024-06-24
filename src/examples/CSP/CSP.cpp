#include "CSP.h"

// setter
// keygen
void BaseCSP::setKeyGenerator(){
    keygen = new KeyGenerator(*context);
}
// evaluator
void BaseCSP::setEvaluator(){
    he_eval = new Evaluator(*context); 
}
// he_sk
void BaseCSP::setCSPHeSecretKey(KeyGenerator* keygen){
    cout << "[CSP] Creating a new HE secret key from the context" << endl;
    he_sk = keygen->secret_key();
}

// getter
// keygen
KeyGenerator* BaseCSP::getKeyGenerator(){
    return keygen;
} 
// he_enc
Evaluator* BaseCSP::getEvaluator(){
    return he_eval;
} 
// CSP he_sk
SecretKey BaseCSP::getCSPHeSecretKey(){
    return he_sk;
}
// Analyst he_pk
PublicKey BaseCSP::getAnalystHePublicKey(string analystId){
    cout << "[CSP] Obtaining Analyst's public key (Analyst Id: " << analystId << ")" << endl;
    return *pkMap[analystId];
}
// Analyst_he_rk
RelinKeys BaseCSP::getAnalystHeRelinKeys(string analystId){
    cout << "[CSP] Obtaining Analyst's relin key (Analyst Id: " << analystId << ")" << endl;
    return *rkMap[analystId];
}
// Analyst_he_gk  
GaloisKeys BaseCSP::getAnalystHeGaloisKeys(string analystId){
    cout << "[CSP] Obtaining Analyst's galois key (Analyst Id: " << analystId << ")" << endl;
    return *gkMap[analystId];
}
// Client_hhe_key
vector<Ciphertext> BaseCSP::getUserHHEKey(string analystId){
    cout << "[CSP] Obtaining User's HHE key (Analyst Id: " << analystId << ")" << endl;
    return encKeysMap[analystId];
}
// vi_se
// vector<uint64_t> BaseCSP::getUserEncData(string analystId){
//     cout << "[CSP] Obtaining User's encrypted data (Analyst Id: " << analystId << ")" << endl;
//     return encDataMap[analystId];  
// } 
// vi_he
vector<Ciphertext> BaseCSP::getHeEncData(string analystId){
    cout << "[CSP] Obtaining User's HE data (Analyst Id: " << analystId << ")" << endl;
    
    return heEncDataMap[analystId];   
}

void BaseCSP::print_vec_Ciphertext(std::vector<seal::Ciphertext> input, size_t size)
{
        seal::seal_byte* buffer = nullptr;

        for (int i = 0; i < size; i++)
        {
            int input_size = input[i].save_size();
            buffer = new seal::seal_byte[input_size];
            input[i].save(buffer, input_size); // write the he_pk to the buffer
            cout << "\n";
            for (int j=0; j < 10; j++){
                std::cout << (int)buffer[j] << " ";
            }

            cout << "input_size: " << input_size << endl;
        }
        std::cout << std::endl;
}

void BaseCSP::print_Ciphertext(seal::Ciphertext input)
{
        seal::seal_byte* buffer = nullptr;

        int input_size = input.save_size();
        buffer = new seal::seal_byte[input_size];
        input.save(buffer, input_size); 

        for (int j=0; j < 10; j++){
                std::cout << (int)buffer[j] << " ";
        }

        std::cout << std::endl;
}


void BaseCSP::heInitialization(){
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

void BaseCSP::decompose(string analystId)
{
    //cout << "[CSP] Analyst Id: " << analystId << endl;
    //cout << "[CSP] Encrpyted data size: " << encDataMap[analystId].size() << endl;
    //cout << "[CSP] Number of Symmetric keys: " << encKeysMap[analystId].size() << endl;

    cout << "[CSP] Making a PASTA_SEAL HHE Object based on the CSP HE sk and Analyst's HE pk (Analyst Id: " << analystId << ")" << endl;
    pasta::PASTA_SEAL HHE(context, 
                          *pkMap[analystId], 
                          he_sk, 
                          *rkMap[analystId], 
                          *gkMap[analystId]);
    

    cout << "[CSP] Decompose: Turning the user's SKE encrypted data c_i into HE encryped c_prime" << endl;
    heEncDataMap[analystId] = HHE.decomposition(encDataMap[analystId],
                                                encKeysMap[analystId], 
                                                config::USE_BATCH);

    print_vec_Ciphertext(heEncDataMap[analystId], heEncDataMap[analystId].size());

    cout << "[CSP] Decompose completed" << endl;

    cout << "[CSP] does HHE decomposition postprocessing on the HE encrypted input" << endl;
    int inputLen = 300;
    size_t num_block = inputLen / HHE.get_plain_size();
    size_t rem = inputLen % HHE.get_plain_size();
    if (rem){ 
        num_block++;
    }
    cout << "There are " << heEncDataMap[analystId].size() << " decomposed HE ciphertexts\n";
    cout << "HHE cipher one block's plain size " << HHE.get_plain_size() << endl;
    cout << "num_block = " << num_block << endl;
    cout << "rem = " << rem << endl;
    cout << "Preparing necessary things to do postprocessing (creating new Galois key, masking, flattening)" << endl;
    vector<int> flatten_gks;
    for (int i = 1; i < num_block; i++)
    {
        flatten_gks.push_back(-(int)(i * HHE.get_plain_size()));
    }

  
    bool use_bsgs = false;
    seal::BatchEncoder analyst_he_benc111(*context);
    // gk_indices = pastahelper::add_gk_indices(use_bsgs, *he_benc);
    gk_indices = pastahelper::add_gk_indices(use_bsgs, analyst_he_benc111);
    utils::print_vec(gk_indices, gk_indices.size(), "gk_indices");
    utils::print_vec(flatten_gks, flatten_gks.size(), "flatten_gks");

    csp_gk_indices = pastahelper::add_some_gk_indices(gk_indices, flatten_gks);
    utils::print_vec(csp_gk_indices, csp_gk_indices.size(), "csp_gk_indices");

    keygen->create_galois_keys(csp_gk_indices, csp_gk);
    keygen->create_relin_keys(csp_rk);
    if (rem != 0)
    {
        vector<uint64_t> mask(rem, 1);
        HHE.mask(heEncDataMap[analystId].back(), mask);
    }

    Ciphertext vi_he_processed;
    HHE.flatten(heEncDataMap[analystId], vi_he_processed, csp_gk);  // vi_he_processed = hhe_decomposition = C_prime
    std::cout<< "print vi_he_processed: " << std::endl;
    print_Ciphertext(vi_he_processed);



    // Check
    utils::print_line(__LINE__);
    cout << "(Check) Decrypts processed, decomposed HE input vector using Analyst's HE secret key\n";
    SecretKey analyst_he_sk = *AnalystSkMap[analystId];
    seal::BatchEncoder analyst_he_benc(*context);
    vector<int64_t> vi_he_processed_decrypted = sealhelper::decrypting(vi_he_processed,
                                                                       analyst_he_sk,
                                                                       analyst_he_benc,
                                                                       *context,
                                                                       inputLen);
    cout << "input vector vi_he_processed_decrypted.size() = " << vi_he_processed_decrypted.size() << ";\n";
    utils::print_vec(vi_he_processed_decrypted, vi_he_processed_decrypted.size(), "vi_he_decrypted_processed");
    // if (vi_he_processed_decrypted.size() != vi.size())
    // {
    //     throw logic_error("The decrypted HE input vector after decomposition has different length than the plaintext version!");
    // }
} 

/*void BaseCSP::evaluateModel(string analystId){
        utils::print_line(__LINE__);
        cout << "CSP evaluates the HE weights on the decomposed HE data" << endl;
        sealhelper::packed_enc_multiply(vi_he_processed, 
                                        wcMap[analystId][0],
                                        encrypted_product, 
                                        *he_eval); // encrypted_product = C_res

        cout << "encrypted_product size before relinearization = " << encrypted_product.size() << endl;
        he_eval->relinearize_inplace(encrypted_product, csp_rk);
        cout << "encrypted_product size after relinearization = " << encrypted_product.size() << endl;

        // check
        utils::print_line(__LINE__);
        std::cout << "(Check) Decrypt the encrypted product to check" << std::endl; 
        SecretKey analyst_he_sk = *AnalystSkMap[analystId];
        int inputLen = 300;
        std::vector<int64_t> decrypted_product = sealhelper::decrypting(encrypted_product,
                                                                        analyst_he_sk,
                                                                        *he_benc,
                                                                        *context,
                                                                        inputLen);
        cout << "input vector decrypted_product.size() = " << decrypted_product.size() << ";\n";
        utils::print_vec(decrypted_product, decrypted_product.size(), "decrypted_product");


        // Do encrypted sum on the resulting product vector
        utils::print_line(__LINE__);
        cout << "CSP does encrypted sum on the encrypted vector" << endl;
        // int inputLen = 300;
        sealhelper::encrypted_vec_sum(encrypted_product, 
                                      encrypted_sum_vec, 
                                      *he_eval, 
                                      *gkMap[analystId], 
                                      inputLen);
        cout << "[CSP] Evaluation completed" << endl;
} */

bool BaseCSP::addPublicKey(string analystId, seal_byte* bytes, int size)
{
    cout << "[CSP] Adding public key (Analyst Id: " << analystId << ") and (size=" << size << ")" << endl;
    
    
    for (int i = 0; i < 10; i++) {
        std::cout << (int)bytes[i] << ' ';
    }
    cout << endl;
    

    PublicKey *he_pk = new PublicKey();
    he_pk->load(*context, bytes, size);
    
    pkMap[analystId] = he_pk;

    return true;
}

bool BaseCSP::addRelinKey(string analystId, seal_byte* bytes, int size)
{
    cout << "[CSP] Adding relin key (Analyst Id: " << analystId << ") and (size=" << size << ")" << endl;

    
    for (int i = 0; i < 10; i++) {
        std::cout << (int)bytes[i] << ' ';
    }
    cout << endl;
    

    RelinKeys *he_rk = new RelinKeys();
    he_rk->load(*context, bytes, size);

    rkMap[analystId] = he_rk;

    return true;
}

bool BaseCSP::addGaloisKey(string analystId, seal_byte* bytes, int size)
{
    cout << "[CSP] Adding galois key (Analyst Id: " << analystId << ") and (size=" << size << ")"  << endl;

    
    for (int i = 0; i < 10; i++) {
        std::cout << (int)bytes[i] << ' ';
    }
    cout << endl;
    

    GaloisKeys *he_gk = new GaloisKeys();
    he_gk->load(*context, bytes, size);

    gkMap[analystId] = he_gk;

    return true;
}

bool BaseCSP::addSecretKey(string analystId, seal_byte* bytes, int size){
    cout << "[CSP] Adding secret key (Analyst Id: " << analystId << ") and (size=" << size << ")"  << endl;
    
    
    for (int i = 0; i < 10; i++) {
        std::cout << (int)bytes[i] << ' ';
    }
    cout << endl;
    

    SecretKey *Analyst_he_sk = new SecretKey();
    Analyst_he_sk->load(*context, bytes, size);
    
    AnalystSkMap[analystId] = Analyst_he_sk;

    return true;
}


bool BaseCSP::addEncSymKeys(string analystId, vector<seal_byte*> bytes, vector<int> lengths)
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

bool BaseCSP::addEncSymData(string analystId, vector<uint64_t> values)
{
    cout << "[CSP] Adding Encrypted Symmetric Data (Analyst Id: " << analystId << ")" << endl;

    encDataMap[analystId] = values;
    return true;
}

bool BaseCSP::addEncWeights(string analystId, vector<seal_byte*> bytes, vector<int> size)
{
    cout << "[CSP] Adding Encrypted Weights (Analyst Id: " << analystId << ")" << endl;

    
    /*for (int i = 0; i < 10; i++) {
        std::cout << (int)bytes[i] << ' ';
    }
    cout << endl;*/
    

    vector<Ciphertext> weights;

    for (int i=0; i<bytes.size(); i++)
    {
        Ciphertext* weight = new Ciphertext();
        weight->load(*context, bytes[i], size[i]);
        weights.push_back(*weight);
    }

    // check
    utils::print_line(__LINE__);
    cout << "(Check) [CSP] decrypts the encrypted weight via analyst's he_sk" << endl;  
    SecretKey analyst_he_sk = *AnalystSkMap[analystId];
    Decryptor analyst_he_dec(*context, analyst_he_sk);
    int inputLen = 300;
    matrix::matrix dec_weights_t = sealhelper::decrypt_weight_mat(weights,
                                                                *he_benc,
                                                                analyst_he_dec,
                                                                inputLen);
    cout << "Decrypted Weights: ";
    matrix::print_matrix_shape(dec_weights_t);
    matrix::print_matrix(dec_weights_t);

    wcMap[analystId] = weights;

    return true;
}

