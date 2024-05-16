#include "User.h"

void User::loadDataAndLabel(){
    cout << "User loads his input data from " << config::dataset_input_path << endl;
    data = matrix::read_from_csv(config::dataset_input_path);
    // matrix::print_matrix(data);
    matrix::print_matrix_shape(data);
    matrix::print_matrix_stats(data);
    cout << "User loads his labels data from " << config::dataset_output_path << endl;
    labels = matrix::read_from_csv(config::dataset_output_path);
    // matrix::print_matrix(labels);
    matrix::print_matrix_shape(labels);
    matrix::print_matrix_stats(labels);
}

void User::setUserSymmetricKey(){
    client_sym_key = pastahelper::get_symmetric_key();
}
       
vector<uint64_t> User::getUserSymmetricKey(){
    return client_sym_key;
}

void User::encryptData(vector<uint64_t> client_sym_key){
    size_t data_index = 5;
    vi = data[data_index];
    cout << "User symmetrically encrypts input" << endl;   
    pasta::PASTA SymmetricEncryptor(client_sym_key, config::plain_mod);
    vi_se = pastahelper::symmetric_encrypt_vec(SymmetricEncryptor, vi); // the symmetric encrypted images
    utils::print_vec(vi_se, vi_se.size(), "vi_se");

    cout << "(Check) User decrypts symmetrically encrypted input" << endl;
    vector<uint64_t> vi_dec = pastahelper::symmetric_decrypt_vec(SymmetricEncryptor, vi_se); // the symmetric encrypted images
    utils::print_vec(vi_dec, vi_dec.size(), "vi_dec");
    utils::print_vec(vi, vi.size(), "vi");
}

 void User::encryptSymmetricKey(seal_byte* he_pk_bytes, int size){
    
 }

