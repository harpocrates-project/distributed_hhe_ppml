#include "User.h"
#include "../tests/symmetric_encryption_test.cpp"

void User::generateSymmetricKey() 
{
    cout << "[User] Creating symmetric key" << endl;
    ssk = get_symmetric_key();
}

void User::printData() 
{
    cout << "[User] Plaintext data: ";
    print_vec(x_i, x_i.size(), "x_i");   
}

void User::encryptData()
{
    cout << "[User] Encrypting data using the symmetric key" << endl;
    PASTA_3_MODIFIED_1::PASTA SymmetricEncryptor(ssk, config::plain_mod);
    c_i = SymmetricEncryptor.encrypt(x_i);
    cout << "[User] Encrypted data: ";
    print_vec(c_i, c_i.size(), "c_i");
    TEST::symmetric_data_encryption_test(x_i, c_i, SymmetricEncryptor);
}

void User::encryptSymmetricKey(seal_byte* he_pk_bytes, int size)
{
    cout << "[User] Loading Analyst Public Key" << endl;
    PublicKey *he_pk = new PublicKey();

    he_pk->load(*context, he_pk_bytes, size);

    cout << "[User] Encrypting symmetric key using the Analyst's HE configurations" << endl;
   
    Encryptor* he_enc = new Encryptor(*context, *he_pk);
    c_k = encrypt_symmetric_key(ssk, config::USE_BATCH, *he_benc, *he_enc);
}


int User::getEncSymmetricKeyBytes(seal_byte* &buffer, int index)
{
    //cout << "[User] sym keys vector size: " << c_k.size() << endl;
    
    Ciphertext key = c_k[index];    

    int keySize = key.save_size();
    buffer = new seal_byte[keySize];
    key.save(buffer, keySize);

    cout << "[User] Serialising Enc Sym key at [" << index << "] " << endl;

    /*
    for (int i = 0; i < 10; i++) {
        std::cout << (int)buffer[i] << ' ';
    }

    cout << endl;
    */

    return keySize;
}
