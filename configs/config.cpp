#include <stdint.h>
#include <cstddef>

#include <string>

namespace config
{
    // === General parameters ===
    bool debugging = false;
    bool verbose = false;
    int dry_run = true;          // if true, only run a few examples
    int dry_run_num_samples = 1; // num samples to run when dry_run is true

    // === HE parameters - refer to the PASTA paper's benchmark on PASTA3 with SEAL ===
    int seclevel = 128;
    bool use_bsgs = false;
    bool USE_BATCH = true;
    // --- 17 bits ---
    uint64_t plain_mod = 65537;
    uint64_t mod_degree = 16384;
    // --- 33 bits ---
    // uint64_t plain_mod = 8088322049;
    // uint64_t mod_degree = 32768;
    // --- 60 bits ---
    // uint64_t plain_mod = 1096486890805657601;
    // uint64_t mod_degree = 32768;

    // === General neural network parameters (only used for PocketNN training) ===
    int epoch = 50;
    int mini_batch_size = 4; // CAUTION: Too big minibatch size can cause overflow
    int lr_inv = 50;
    int weight_lower_bound = -127;
    int weight_upper_bound = 128;
    bool save_weights = true;

    // === MNIST parameters (depricated) ===
    int num_test_samples = 5;
    int num_classes = 10;
    int mnist_rows = 28;
    int mnist_cols = 28;
    int dim_input = mnist_rows * mnist_cols;
    int dim_layer1 = 100; // only for the 3-layer MNIST neural net
    int dim_layer2 = 50;  // only for the 3-layer MNIST neural net

    // === Square NN parameters ===
    // int

    // === Paths to the dataset ===

    // === Paths to the dataset and weights ===
    // --- 1FC Model on ECG Data ---
    // std::string dataset_input_path = "data/mit-bih/csv/mitbih_x_test_int.csv";
    // std::string dataset_output_path = "data/mit-bih/csv/mitbih_bin_y_test.csv";
    // std::string save_weight_path = "weights/ecg/ecg_512/fc1_weight_50epochs_bz4.csv";
    // std::string save_bias_path = "weights/ecg/ecg_512/fc1_bias_50epochs_bs4.csv";
    // --- 1FC Model on SpO2 Data ---
    //std::string dataset_input_path = "data/arc/SpO2/SpO2_input_cleaned4%.csv";
    //std::string dataset_output_path = "data/arc/SpO2/SpO2_output_cleaned4%.csv";
    
    // For debugging
    //std::string dataset_input_path = "data/Harpocrates_recordingwise_SIESTA_4percent/c000101_data.txt";
    //std::string dataset_output_path = "data/Harpocrates_recordingwise_SIESTA_4percent/c000101_binaryoutput.txt";
    std::string dataset_input_path = "";
    std::string dataset_output_path = "";

    std::string save_weight_path = "weights/SpO2/qat/quant_fc_5bits_data_2bits_weights.csv";
    std::string save_bias_path = "";
    // --- 2FC Model on MNIST ---
    // std::string dataset_input_path = "data/mnist/2bits_test_mnist_data.csv";
    // std::string dataset_output_path = "data/mnist/2bits_test_mnist_labels.csv";
    // std::string save_weight_path = "weights/mnist/qat/quant_2fc_2bits_mnist_plain_2bits_weights";
    // std::string save_bias_path = "";
    // --- 2FC Model on FMNIST ---

    // === Parameters to run experiments ===
    // uint64_t NUM_RUN = 50;
    // uint64_t NUM_VEC = 1;
    // size_t user_vector_size = 4;
}
