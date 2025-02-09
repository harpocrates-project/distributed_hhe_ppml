#include "User.h"

/**
Load data and label for NN calculation
*/
void User::loadDataAndLabel(string dataSet)
{

    cout << "[User] Loading his input data" << dataSet << endl;
    data = matrix::read_from_csv(dataSet);
    // matrix::print_matrix(data);
    matrix::print_matrix_shape(data);
    matrix::print_matrix_stats(data);

    /*
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
    */
}

/**
Create a symmetric key
*/
void User::setSymmetricKey()
{
    client_sym_key = pastahelper::get_symmetric_key();
}

/**
Set up a data set name for NN calculation
*/
void User::setDataSet(string data_set){
    dataSet = data_set;
}

/**
Return the symmetric key
*/      
vector<uint64_t> User::getSymmetricKey()
{
    return client_sym_key;
}

/**
Return the datas set name for NN calculation
*/
string User::getDataSet(){
    return dataSet;
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
void User::encryptData(vector<uint64_t> client_sym_key, int numRecords)
{ 
    pasta::PASTA SymmetricEncryptor(client_sym_key, config::plain_mod);

    for (size_t i = 1; i < numRecords; i++)
    {
        cout << "[User] Symmetrically encrypting input" << endl; 
        vi = data[i]; 
        vi_se = pastahelper::symmetric_encrypt_vec(SymmetricEncryptor, vi); // the symmetric encrypted images
        utils::print_vec(vi_se, vi_se.size(), "vi_se");

        array.push_back(vi_se);

        cout << "(Check) [User] Decrypting symmetrically encrypted input" << endl;
        vector<uint64_t> vi_dec = pastahelper::symmetric_decrypt_vec(SymmetricEncryptor, vi_se); // the symmetric encrypted images
        utils::print_vec(vi_dec, vi_dec.size(), "vi_dec");

        cout << "[User] Plaintext input" << endl;
        utils::print_vec(vi, vi.size(), "vi");
    }

    for (int i = 0; i < array.size(); i++)
    {
        utils::print_vec(array[i], array[i].size(), "array[i]");
    }
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
vector <vector<uint64_t>> User::getEncryptedData() 
{ 
    // return vi_se; 
    return array;
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

    


