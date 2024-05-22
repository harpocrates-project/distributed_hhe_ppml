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
    cout << "(Check) Decrypted result" << endl;
    utils::print_vec(vi_dec, vi_dec.size(), "vi_dec");
    cout << "(Check) Plaintext" << endl;
    utils::print_vec(vi, vi.size(), "vi");
}

 void User::encryptSymmetricKey(vector<uint64_t> client_sym_key, seal_byte* he_pk_bytes, int size){
    cout << "[User] Loading Analyst Public Key" << endl;   
    PublicKey *he_pk = new PublicKey();
    he_pk->load(*context, he_pk_bytes, size);
    cout << "[User] Encrypting symmetric key using the Analyst's HE configurations" << endl;
    Encryptor* he_enc = new Encryptor(*context, *he_pk);
    client_hhe_key = pastahelper::encrypt_symmetric_key(
            client_sym_key, 
            config::USE_BATCH, 
            *he_benc, 
            *he_enc);
    //utils::print_vec(client_sym_key, client_sym_key.size(), "client_sym_key");   
}

vector<Ciphertext> User::getEncryptedSymmetricKeys() { 
    return client_hhe_key; 
}

int User::getEncSymmetricKeyBytes(seal_byte* &buffer, int index)
{
    //cout << "[User] sym keys vector size: " << c_k.size() << endl;
    
    Ciphertext key = client_hhe_key[index];    

    int keySize = key.save_size();
    buffer = new seal_byte[keySize];
    key.save(buffer, keySize);

    cout << "[User] Serialising Enc Sym key at [" << index << "] " << endl;

    
    for (int i = 0; i < 10; i++) {
        std::cout << (int)buffer[i] << ' ';
    }

    cout << endl;
    

    return keySize;
}

void User::computingCheck(){
    utils::print_line(__LINE__);
    cout << "(Check) Computing in plain on 1 input vector" << endl;
    matrix::vector vo_p(1);
    size_t data_index = 5;
    matrix::vector vi = data[data_index];
    int64_t gt_out = labels[data_index][0];
    cout << "input vector vi.size() = " << vi.size() << ";\n";
    // utils::print_vec(vi, vi.size(), "vi");


    // copy codes from Analyst
    matrix::matrix weights;
    if (config::debugging){
        weights = matrix::read_from_csv("../../../" + config::save_weight_path);
    } else {
        weights = matrix::read_from_csv(config::save_weight_path);
    }
    matrix::matrix weights_t = matrix::transpose(weights);


    matrix::matMulVecNoModulus(vo_p, weights_t, vi);  // vo_p = weight * data
    cout << "plain output vector vo.size() = " << vo_p.size() << ";\n";
    utils::print_vec(vo_p, vo_p.size(), "vo_p");
    int64_t plain_pred = utils::int_sigmoid(vo_p[0]);  // activation function (sigmod)
    cout << "plain prediction = " << plain_pred << " | ";
    cout << "groundtruth label = " << gt_out << ";\n";
}
    


