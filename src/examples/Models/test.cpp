#include "test.h"

using namespace std;
using namespace seal;
using namespace sealhelper;
using namespace pastahelper;



void BaseModel::test_ini(){
    keygen->create_public_key(he_pk); // HE_pk
    he_sk = keygen->secret_key(); // HE_sk

    he_enc = new Encryptor(*context, he_pk); 
    he_dec = new Decryptor(*context, he_sk);

    cout << " hello world! " << endl;
}  


// he_benc
BatchEncoder* BaseModel::getBatchEncoder(){
    return he_benc;
}
// he_sk
SecretKey BaseModel::getAnalystHeSecretKey(){
    return he_sk;
}
// he_pk
PublicKey BaseModel::getAnalystHePublicKey(){
    return he_pk;
}
// he_enc
Encryptor* BaseModel::getEncryptor(){
    return he_enc;
} 
// he_dec
Decryptor* BaseModel::getDecryptor(){
    return he_dec;
} 


void hhe_pktnn_1fc::func(PublicKey he_pk,BatchEncoder* he_benc,Encryptor* he_enc,Decryptor* he_dec) { 
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

int main()
{    
    BaseModel* ptr = new hhe_pktnn_1fc();

    ptr->test_ini();

    cout << "=======================" << endl;
    ptr->func(
        ptr->getAnalystHePublicKey(),
        ptr->getBatchEncoder(),
        ptr->getEncryptor(),
        ptr->getDecryptor()
    );

     return 0;
}
