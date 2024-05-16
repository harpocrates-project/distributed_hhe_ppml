#include "Analyst.h"


// setter
// keygen
void BaseAnalyst::setKeyGenerator(){
    keygen = new KeyGenerator(*context);
}
// he_benc
void BaseAnalyst::setBatchEncoder(){
    he_benc = new BatchEncoder(*context);
}
// he_sk
void BaseAnalyst::setAnalystHeSecretKey(KeyGenerator* keygen){
    he_sk = keygen->secret_key();
}
// he_pk
void BaseAnalyst::setAnalystHePublicKey(KeyGenerator* keygen){
    keygen->create_public_key(he_pk); // HE_pk
}   
// he_rk
void BaseAnalyst::setAnalystHeRelinKeys(KeyGenerator* keygen){
    keygen->create_relin_keys(he_rk);
}
// he_gk
void BaseAnalyst::setAnalystHeGaloisKeys(BatchEncoder* he_benc, KeyGenerator* keygen){
    bool use_bsgs = false;
    vector<int> gk_indices = add_gk_indices(use_bsgs, *he_benc);
    keygen->create_galois_keys(gk_indices, he_gk);  // HE_gk
}
// encryptor
void BaseAnalyst::setEncryptor(){
    he_enc = new Encryptor(*context, he_pk); 
}
// evaluator
void BaseAnalyst::setEvaluator(){
    he_eval = new Evaluator(*context); 
}
// decryptor
void BaseAnalyst::setDecryptor(){
    he_dec = new Decryptor(*context, he_sk);
}

// getter
// keygen
KeyGenerator* BaseAnalyst::getKeyGenerator(){
    return keygen;
} 
// he_benc
BatchEncoder* BaseAnalyst::getBatchEncoder(){
    return he_benc;
}
// he_sk
SecretKey BaseAnalyst::getAnalystHeSecretKey(){
    return he_sk;
}
// he_pk
PublicKey BaseAnalyst::getAnalystHePublicKey(){
    return he_pk;
}
// he_rk
RelinKeys BaseAnalyst::getAnalystHeRelinKeys(){
    return he_rk;
}
// he_gk
GaloisKeys BaseAnalyst::getAnalystHeGaloisKeys(){
    return he_gk;
}
// he_enc
Encryptor* BaseAnalyst::getEncryptor(){
    return he_enc;
} 
// he_enc
Evaluator* BaseAnalyst::getEvaluator(){
    return he_eval;
} 
// he_dec
Decryptor* BaseAnalyst::getDecryptor(){
    return he_dec;
} 
// context
shared_ptr<SEALContext> BaseAnalyst::getContext(){ 
    return context; 
}




void BaseAnalyst::heInitialization(){
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


void BaseAnalyst::generateHEKeys(){
    std::cout << "Analyst constructs the HE context"
              << "\n";
    print_parameters(*context);

    cout << "[Analyst] Creating HE keys, batch encoder, encryptor and evaluator from the context" << endl;
    
    heInitialization();
    setAnalystHeSecretKey(keygen); // he_sk
    setAnalystHePublicKey(keygen); // he_pk
    setAnalystHeRelinKeys(keygen); // he_rk
    setAnalystHeGaloisKeys(he_benc, keygen); // he_gk

    // he_enc = new Encryptor(*context, he_pk);   // HE_encryptor
    // he_dec = new Decryptor(*context, he_sk);
}



int BaseAnalyst::getPublicKeyBytes(seal_byte* &buffer)
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



void Analyst_hhe_pktnn_1fc::func(PublicKey he_pk,BatchEncoder* he_benc,Encryptor* he_enc,Decryptor* he_dec) { 
    cout << "Analyst loads the pretrained weights"
         << "\n";
    matrix::matrix weights;
    if (config::debugging){
        weights = matrix::read_from_csv("../../../" + config::save_weight_path);
    } else {
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

    utils::print_line(__LINE__);
    std::cout << "Analyst encrypts the weights using HE" << std::endl;
    std::vector<seal::Ciphertext> enc_weights_t = sealhelper::encrypt_weight_mat(weights_t,
                                                                                 he_pk,
                                                                                 *he_benc,
                                                                                 *he_enc);

    int inputLen = 300; 
    utils::print_line(__LINE__);
    std::cout << "(Check) Analyst decrypts the encrypted weight" << std::endl;
    matrix::matrix dec_weights_t = sealhelper::decrypt_weight_mat(enc_weights_t,
                                                                  *he_benc,
                                                                  *he_dec,
                                                                  inputLen);
    std::cout << "Decrypted Weights: ";
    matrix::print_matrix_shape(dec_weights_t);
    matrix::print_matrix(dec_weights_t);
}

