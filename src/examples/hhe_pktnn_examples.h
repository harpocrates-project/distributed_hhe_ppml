#pragma once

#include <iostream>
#include <vector>
#include <chrono>
#include <cassert>

#include <pocketnn/pktnn.h>
#include <seal/seal.h>

#include "../../configs/config.h"
#include "../util/sealhelper.h"
#include "../util/pastahelper.h"
#include "../util/utils.h"
#include "../util/matrix.h"
#include "../util/checks.h"
#include "../pasta/pasta_3_plain.h"
#include "../pasta/pasta_3_seal.h"
#include "../../tests/ecg_tests.h"
#include "../../tests/ecg_tests.h"

using namespace std;
using namespace seal;
using namespace sealhelper;
using namespace pastahelper;

namespace hhe_pktnn_examples
{
    struct Analyst
    {
        // the model weights and bias in plaintext
        pktnn::pktmat weight; // plaintext weight
        pktnn::pktmat bias;   // plaintext bias
        // the model weights and bias in ciphertext
        std::vector<seal::Ciphertext> enc_weight; // the encrypted weight
        std::vector<seal::Ciphertext> enc_bias;   // the encrypted bias
        // the HE keys
        seal::PublicKey he_pk;
        seal::SecretKey he_sk;
        seal::RelinKeys he_rk;
        seal::GaloisKeys he_gk;
        // the HE encrypted results from the csp
        std::vector<seal::Ciphertext> *enc_results;
        // the HE decrypted results
        std::vector<std::vector<int64_t>> dec_results;
        // the final predictions
        std::vector<int64_t> predictions;
    };

    struct Client
    {
        // the symmetric keys
        std::vector<uint64_t> k;           // the secret symmetric keys
        std::vector<seal::Ciphertext> c_k; // the HE encrypted symmetric keys
        // the plaintext data
        pktnn::pktmat testData;   // the plaintext test images
        pktnn::pktmat testLabels; // the plaintext test labels
        // the encrypted data
        std::vector<std::vector<uint64_t>> cs; // the symmetric encrypted data
    };

    struct CSP
    {
        seal::PublicKey *he_pk;
        seal::RelinKeys *he_rk;
        seal::GaloisKeys *he_gk;
        std::vector<seal::Ciphertext> *enc_weight; // the encrypted weight
        std::vector<seal::Ciphertext> *enc_bias;   // the encrypted bias
        // things received from the client / data owner
        std::vector<seal::Ciphertext> *c_k;     // the HE encrypted symmetric keys
        std::vector<std::vector<uint64_t>> *cs; // the symmetric encrypted data

        // the HE secret key needed to construct the HHE object
        seal::SecretKey he_sk;
        // the HE encrypted data after decomposition (and post-process if needed) of the
        // user's symmetric encrypted test data
        std::vector<seal::Ciphertext> c_primes;
        // the HE encrypted results that will be sent to the Analyst
        std::vector<seal::Ciphertext> enc_results;
    };

    int hhe_pktnn_ecg_inference();

    /*
        Work in Progress
    */
    int hhe_pktnn_1fc_inference(const std::string &dataset); // encrypted inference protocol on SpO2 / MNIST data for the 1-layer nn
    int hhe_pktnn_2fc_inference(const std::string &dataset); // encrypted inference protocol on MNIST / FMNIST data for the 2fc layer nn with square activation

    void print_vec_Ciphertext(std::vector<seal::Ciphertext> input, size_t size);
    void print_Ciphertext(seal::Ciphertext input);

    void symmetric_key_he_encryption_test(std::vector<seal::Ciphertext> enc_ssk,
                                          std::vector<uint64_t> ssk,
                                          bool USE_BATCH,
                                          std::shared_ptr<seal::SEALContext> context,
                                          const SecretKey &sk,
                                          const PublicKey &pk,
                                          const RelinKeys &rk,
                                          const GaloisKeys &gk,
                                          const BatchEncoder &he_benc,
                                          const Encryptor &he_enc);

} // end of hhe_pktnn_examples namespace
