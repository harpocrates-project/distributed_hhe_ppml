#include "User.h"

/**
Load data and label for NN calculation
*/
void User::loadDataAndLabel()
{
    cout << "[User] Loading his input data from " << config::dataset_input_path << endl;
    data = matrix::read_from_csv(config::dataset_input_path);
    // matrix::print_matrix(data);
    matrix::print_matrix_shape(data);
    matrix::print_matrix_stats(data);
    cout << "[User] Loading his labels data from " << config::dataset_output_path << endl;
    labels = matrix::read_from_csv(config::dataset_output_path);
    // matrix::print_matrix(labels);
    matrix::print_matrix_shape(labels);
    matrix::print_matrix_stats(labels);
}

/**
Create a symmetric key
*/
void User::setSymmetricKey()
{
    client_sym_key = pastahelper::get_symmetric_key();
}

/**
Return the symmetric key
*/      
vector<uint64_t> User::getSymmetricKey()
{
    return client_sym_key;
}

/**
Helper function to print the first ten bytes of the seal_byte input
*/
void User::print_seal_bytes(seal_byte* buffer)
{
    for (int i = 0; i < 10; i++)
    {
        cout << (int)buffer[i] << ' ';
    }
    cout << "... ..." << endl;
}

/**
Helper function to print the ciphertext vector
*/
void User::print_vec_Ciphertext(vector<Ciphertext> input, size_t size)
{
        seal_byte* buffer = nullptr;

        for (int i = 0; i < size; i++)
        {
            int input_size = input[i].save_size();
            buffer = new seal_byte[input_size];
            input[i].save(buffer, input_size); 
            print_seal_bytes(buffer);
        }
}

/**
Encrypt the plaintext data
*/
void User::encryptData(vector<uint64_t> client_sym_key)
{
    size_t data_index = 5;
    vi = data[data_index];
    cout << "[User] Symmetrically encrypting input" << endl;   
    pasta::PASTA SymmetricEncryptor(client_sym_key, config::plain_mod);
    vi_se = pastahelper::symmetric_encrypt_vec(SymmetricEncryptor, vi); // the symmetric encrypted images
    utils::print_vec(vi_se, vi_se.size(), "vi_se");

    cout << "(Check) [User] Decrypting symmetrically encrypted input" << endl;
    vector<uint64_t> vi_dec = pastahelper::symmetric_decrypt_vec(SymmetricEncryptor, vi_se); // the symmetric encrypted images
    utils::print_vec(vi_dec, vi_dec.size(), "vi_dec");

    cout << "[User] Plaintext input" << endl;
    utils::print_vec(vi, vi.size(), "vi");
}

/**
Encrypt the plaintext symmetric key
*/
 void User::encryptSymmetricKey(vector<uint64_t> client_sym_key, seal_byte* analyst_he_pk_bytes, int size)
 {
    cout << "[User] Loading Analyst Public key" << endl;   
    //print_seal_bytes(he_pk_bytes);

    PublicKey *analyst_he_pk = new PublicKey();
    analyst_he_pk->load(*context, analyst_he_pk_bytes, size);
    cout << "[User] Encrypting symmetric key using HE (the HHE key)" << endl;
    Encryptor* analyst_he_enc = new Encryptor(*context, *analyst_he_pk);

    client_hhe_key = pastahelper::encrypt_symmetric_key(client_sym_key, 
                                                        config::USE_BATCH, 
                                                        *he_benc, 
                                                        *analyst_he_enc); 
    cout<< "The User HHE key " << endl;
    print_vec_Ciphertext(client_hhe_key, client_hhe_key.size());  
}

/**
Return the encrypted symmetric key
*/
vector<Ciphertext> User::getEncryptedSymmetricKey() 
{ 
    return client_hhe_key; 
}

/**
Return the encrypted data
*/
vector<uint64_t> User::getEncryptedData() 
{ 
    return vi_se; 
}

/**
Return the byte size for encrypted symmetric key
*/
int User::getEncryptedSymmetricKeyBytes(seal_byte* &buffer, int index)
{
    //cout << "[User] sym keys vector size: " << c_k.size() << endl;
    
    Ciphertext key = client_hhe_key[index];    

    int keySize = key.save_size();
    buffer = new seal_byte[keySize];
    key.save(buffer, keySize);

    cout << "[User] Serialising encrypted symmetric key" << endl;
    print_seal_bytes(buffer);

    return keySize;
}

/*void User::computingCheck()
{
    utils::print_line(__LINE__);
    cout << "(Check) Computing in plain on 1 input vector" << endl;
    matrix::vector vo_p_1(1);
    size_t data_index_1 = 5;
    matrix::vector vi_1 = data[data_index_1];
    int64_t gt_out_1 = labels[data_index_1][0];
    cout << "input vector vi.size() = " << vi_1.size() << ";\n";
    utils::print_vec(vi_1, vi_1.size(), "vi");

    // copy codes from Analyst
    matrix::matrix weights;
    if (config::debugging)
    {
        weights = matrix::read_from_csv("../../../" + config::save_weight_path);
    } 
    else 
    {
        weights = matrix::read_from_csv(config::save_weight_path);
    }
    matrix::matrix weights_t = matrix::transpose(weights);

    matrix::matMulVecNoModulus(vo_p_1, weights_t, vi_1);  // vo_p = weight * data
    cout << "plain output vector vo.size() = " << vo_p_1.size() << ";\n";
    utils::print_vec(vo_p_1, vo_p_1.size(), "vo_p");
    int64_t plain_pred = utils::int_sigmoid(vo_p_1[0]);  // activation function (sigmod)
    cout << "plain prediction = " << plain_pred << " | ";
    cout << "groundtruth label = " << gt_out_1 << ";\n";
}*/
    


