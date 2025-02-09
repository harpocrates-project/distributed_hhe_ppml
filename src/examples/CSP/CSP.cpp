#include "CSP.h"
#include <iostream>
#include <fstream>
#include <thread>
#include <vector>
#include <chrono>

using namespace std;
using namespace std::chrono;

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
    std::cout << "[CSP] Creating a new HE secret key from the context" << std::endl;
    csp_he_sk = csp_keygen->secret_key();
}

/**
Set he_enc_data_processed_map
*/
void BaseCSP::setHHEEncDataProcessedMap(string analystId, vector<Ciphertext> ciphertexts)
{
    he_enc_data_processed_map[analystId] = ciphertexts;
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
vector<vector<Ciphertext>> BaseCSP::getHEEncryptedData(string analystId)
{
    return he_enc_data_map[analystId];   
}

/** 
Return the Sum of the HE_ENC_Product
*/
vector<Ciphertext> BaseCSP::getHESumEncProduct(string analystId)
{
    return he_sum_enc_product_map[analystId];
}

/**
Return the encrypted result calculated by CSP via HHE decomposition and evaluation
*/

int BaseCSP::getEncryptedResultBytes(string analystId, seal_byte* &buffer, int index)
{
    Ciphertext encrypted_sum_vec = he_sum_enc_product_map[analystId].at(index);

    int encrypted_sum_vec_size = encrypted_sum_vec.save_size();
    buffer = new seal_byte[encrypted_sum_vec_size];
    encrypted_sum_vec.save(buffer, encrypted_sum_vec_size);

    cout << "[CSP] Serialised encrypted result for Analyst (AnalystId: " << analystId << ", size: " << encrypted_sum_vec_size << ")" << endl;
    print_seal_bytes(buffer);
    
    return encrypted_sum_vec_size; 
}

/** 
Return the HE encrypted processed data 
*/
vector<Ciphertext> BaseCSP::getHEEncDataProcessedMapValue(string analystId)
{
    return he_enc_data_processed_map[analystId];
}

/** 
Return the first value of encrypted weights map
*/
Ciphertext BaseCSP::getEncWeightsMapFirstValue(string analystId)
{
    return enc_weights_map[analystId][0];
}

/** 
Return the CSP Relin keys value
*/
RelinKeys BaseCSP::getCSPHERelinKeysMapValue(string analystId)
{
    return *csp_he_rk_map[analystId];
}

/** 
Return the CSP Galois keys value
*/
GaloisKeys BaseCSP::getCSPHEGaloisKeysMapValue(string analystId)
{
    return *csp_he_gk_map[analystId];
}

/** 
Return the HE encrypted processed data 
*/
vector<Ciphertext> BaseCSP::getHEEncDataProcessedMap(string analystId)
{
    return he_enc_data_processed_map[analystId];
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
void BaseCSP::decompose(string analystId, int inputLen)
{
    cout << "[CSP] Making a PASTA_SEAL HHE object based on the CSP's HE sk and Analyst's HE pk, rk, gk (Analyst Id: " << analystId << ")" << endl;
    pasta::PASTA_SEAL HHE(context, 
                          getAnalystHEPublicKey(analystId), 
                          getHESecretKey(), 
                          getAnalystHERelinKeys(analystId), 
                          getAnalystHEGaloisKeys(analystId));

    cout << "[CSP] Decomposition: CSP does HHE decomposition to turn User's symmetric input into HE input" << endl;

    auto start = high_resolution_clock::now();

    // Perform decomposition
    performDecomposition(analystId, HHE);

    // Perform masking
    performMasking(analystId, inputLen, HHE);

    // Perform flattening
    performFlattening(analystId, HHE);

    auto end = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(end - start);
    cout << "Total decompose time: " << duration.count() << " ms" << endl;

    cout << "The HHE decomposition postprocessing result is " << endl; // vi_he_processed
    for (Ciphertext record : he_enc_data_processed_map[analystId])
            print_Ciphertext(record);
} 

void BaseCSP::performDecomposition(std::string analystId, pasta::PASTA_SEAL& HHE)
{
    for (vector<uint64_t> record : enc_data_map[analystId])
    {
        he_enc_data_map[analystId].push_back(HHE.decomposition(record,
                                                getUserEncryptedSymmetricKey(analystId), 
                                                config::USE_BATCH));
    }
}

void BaseCSP::performMasking(std::string analystId, int inputLen, pasta::PASTA_SEAL& HHE)
{
    size_t rem = inputLen % HHE.get_plain_size();

    if (rem != 0)
    {
        vector<uint64_t> mask(rem, 1);
        for (vector<Ciphertext> record : he_enc_data_map[analystId])
            HHE.mask(record.back(), mask);
    }
}

void BaseCSP::performFlattening(std::string analystId, pasta::PASTA_SEAL& HHE)
{
    Ciphertext tmp;
    for (vector<Ciphertext> record : he_enc_data_map[analystId])
    {
        HHE.flatten(record, 
                    tmp, 
                    getCSPHEGaloisKeysMapValue(analystId));  // vi_he_processed = hhe_decomposition = C_prime
        he_enc_data_processed_map[analystId].push_back(tmp);
    }
}

/**
HHE evaluation
*/
void CSP_hhe_pktnn_1fc::evaluateModel(string analystId, int inputLen)
{
        cout << "[CSP] Evaluating the HE weights on the decomposed HE data" << endl;

        Ciphertext tmp;
        for (Ciphertext record : getHEEncDataProcessedMapValue(analystId))
        {
            sealhelper::packed_enc_multiply(record, 
                                            getEncWeightsMapFirstValue(analystId),
                                            tmp, 
                                            *getEvaluator()); 
            he_enc_product_map[analystId].push_back(tmp);
        }

        Ciphertext tmp1;
        for (Ciphertext record : he_enc_product_map[analystId]) 
        {
            cout << "encrypted_product size before relinearization = " << record.size() << endl;
            getEvaluator()->relinearize_inplace(record, getCSPHERelinKeysMapValue(analystId));
            cout << "encrypted_product size after relinearization = " << record.size() << endl;

        // Do encrypted sum on the resulting product vector
            cout << "[CSP] Executing encrypted sum on the encrypted vector" << endl;

            sealhelper::encrypted_vec_sum(record, 
                                        tmp1, 
                                        *getEvaluator(), 
                                        getAnalystHEGaloisKeys(analystId), 
                                        inputLen);
            he_sum_enc_product_map[analystId].push_back(tmp1);                            
        }

        print_vec_Ciphertext(he_sum_enc_product_map[analystId], he_sum_enc_product_map[analystId].size());

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
bool BaseCSP::addUserEncryptedData(string analystId, vector <vector<uint64_t>> values)
{
    cout << "[CSP] Adding User encrypted data (AnalystId: " << analystId << ")" << endl;

    enc_data_map[analystId] = values;
    return true;
}

/**
Add Analyst UUID
*/
bool BaseCSP::addAnalystUUID(string analystId, string analystUUID)
{
    cout << "[CSP] Adding Analyst's UUID (AnalystId: " << analystId << ")" << endl;

    analyst_uuid_map[analystId] = analystUUID;

    return true;
}

bool BaseCSP::addAnalystUUIDtoIDMap(string analystUUID, string analystId)
{
    cout << "[CSP] Adding Analyst's UUID to ID map (AnalystId: " << analystId << ")" << endl;

    analyst_uuid_id_map[analystUUID] = analystId;

    return true;
}

/**
Return the Analyst's UUID
*/
string BaseCSP::getAnalystUUID(string analystId)
{
    return analyst_uuid_map[analystId];
}

string BaseCSP::getAnalystIdfromUUID(string analystId)
{
    return analyst_uuid_id_map[analystId];
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

/** 
Write HHE Decomposition data from memory to a file
*/
bool BaseCSP::writeHHEDecompositionDataToFile(string fileName, vector<Ciphertext> input)
{
    //fileName = fileName;
    ofstream out(fileName, ios::binary);
    if (!out.is_open()) {
        throw ios_base::failure("Failed to open file for writing");
    }

    // Save the size of the vector
    size_t size = input.size();
    out.write(reinterpret_cast<const char*>(&size), sizeof(size));

    // Save each ciphertext
    for (const auto &ciphertext : input) {
        ciphertext.save(out);
    }

    out.close();

    cout << "The HHE decomposition data has been written to a file" << endl; 

    return true;
}

/** 
Read HHE Decomposition data from a file
*/
bool BaseCSP::readHHEDecompositionDataFromFile(string fileName, vector<Ciphertext>& output)
{
    ifstream in(fileName, ios::binary);
    if (!in.is_open()) {
        throw ios_base::failure("Failed to open file for reading");
    }

    // Read the size of the vector
    size_t size;
    in.read(reinterpret_cast<char*>(&size), sizeof(size));

    // Resize the vector and load each ciphertext
    
    output.resize(size);
    for (size_t i = 0; i < size; ++i) {
        output[i].load(*context, in);
    }

    in.close();

    cout << "Read HHE decomposition data from a file" << endl; 
    for (Ciphertext t : output)
        print_Ciphertext(t);

    return true;
}

/** 
Convert HHEDecomp data from bytes to Ciphertext
*/
bool BaseCSP::deserializeCiphertexts(const google::protobuf::RepeatedPtrField<std::string>& serializedDataList, 
                            std::vector<Ciphertext>& ciphertexts, 
                            std::string& errorMessage)
{
    try {
        // Check if serialized data list is empty
        if (serializedDataList.empty()) {
            errorMessage = "Received empty HHE decomposition data.";
            return false;
        }

        // Concatenate all strings in the RepeatedPtrField into one continuous string
        std::ostringstream concatenatedData;
        for (const auto& data : serializedDataList) {
            concatenatedData << data;
        }

        std::istringstream inputStream(concatenatedData.str());

        // Read the size of the ciphertext array
        size_t arraySize;
        inputStream.read(reinterpret_cast<char*>(&arraySize), sizeof(arraySize));
        if (!inputStream.good()) {
            errorMessage = "Failed to read the size of the ciphertext array.";
            return false;
        }

        std::cout << "Array size: " << arraySize << std::endl;

        // Resize the vector to hold the ciphertexts
        ciphertexts.resize(arraySize);

        // Deserialize each ciphertext
        for (size_t i = 0; i < arraySize; ++i) {
            try {
                ciphertexts[i].load(*context, inputStream);
                if (!inputStream.good()) {
                    errorMessage = "Failed to load a ciphertext from the stream.";
                    return false;
                }
            } catch (const std::exception& e) {
                errorMessage = "Error deserializing ciphertext: " + std::string(e.what());
                return false;
            }
        }

        return true;

    } catch (const std::exception& e) {
        std::cerr << "Exception in deserializeCiphertexts: " << e.what() << std::endl;
        errorMessage = e.what();
        return false;
    } 
}

void CSPParallel_hhe_pktnn_1fc::performDecomposition(std::string analystId, pasta::PASTA_SEAL &HHE)
{
    unsigned int num_threads = std::thread::hardware_concurrency();
    std::vector<std::thread> thread_pool;
    std::mutex mtx;

    std::cout << "Using up to " << num_threads << " threads for decomposition" << std::endl;

    auto decompose_task = [&](vector<uint64_t> record,
                              vector<vector<Ciphertext>> &he_enc_data,
                              const vector<Ciphertext> &userEncryptedSymmetricKey)
    {
        auto result = HHE.decomposition(record, userEncryptedSymmetricKey, config::USE_BATCH);
        {
            std::lock_guard<std::mutex> lock(mtx);
            he_enc_data.push_back(result);
        }
    };

    auto &he_enc_data = he_enc_data_map[analystId];
    const auto &userEncryptedSymmetricKey = getUserEncryptedSymmetricKey(analystId);
    size_t num_of_active_threads = 1;

    const auto &records = enc_data_map[analystId];
    for (size_t i = 0; i < records.size(); ++i)
    {
        const auto &record = records[i];
        size_t num_of_record_blocks = HHE.get_num_of_blocks(record);

        std::cout << "Processing record " << i << " with " << num_of_record_blocks << " blocks" << std::endl;

        if (num_of_active_threads >= num_threads)
        {
            std::cout << "Max number of threads reached. Waiting for current threads to finish." << std::endl;
            for (auto &th : thread_pool)
            {
                th.join();
            }
            thread_pool.clear();
            num_of_active_threads = 0;
        }

        thread_pool.emplace_back(decompose_task, record, std::ref(he_enc_data), std::ref(userEncryptedSymmetricKey));
        num_of_active_threads = thread_pool.size() * num_of_record_blocks;
        std::cout << "Current number of active threads: " << num_of_active_threads << std::endl;
    }

    for (auto &th : thread_pool)
    {
        th.join();
    }

    std::cout << "All threads finished. Printing results." << std::endl;
    for (auto &record : he_enc_data)
    {
        print_vec_Ciphertext(record, record.size());
    }
}