#include <iostream>
#include <string>
#include <istream>
#include <ostream>
#include "hhe.pb.h"
#include "../../Common.h"

class DecompositionServer {
public:
    bool deserializeRequest(std::istream& input);
    bool performDecomposition();
    bool serializeResponse(std::ostream& output);
    void printResult();

private:
    hheproto::DecompositionRequest request;
    hheproto::DecompositionResponse response;
    std::shared_ptr<seal::SEALContext> context;
    seal::PublicKey pk;
    seal::SecretKey sk;
    seal::RelinKeys rk;
    seal::GaloisKeys gk;
    std::vector<uint64_t> record;
    std::vector<seal::Ciphertext> userEncryptedSymmetricKey;
    std::vector<seal::Ciphertext> result;
};

bool DecompositionServer::deserializeRequest(std::istream& input) {
    if (!request.ParseFromIstream(&input)) {
        std::cerr << "Failed to parse input as DecompositionRequest protobuf message" << std::endl;
        return false;
    }

    // Create the SEALContext
    context = get_seal_context(config::plain_mod, config::mod_degree, config::seclevel);

    // Deserialize the keys
    {
        std::istringstream pk_stream(request.public_key());
        pk.load(*context, pk_stream);
    }
    {
        std::istringstream sk_stream(request.secret_key());
        sk.load(*context, sk_stream);
    }
    {
        std::istringstream rk_stream(request.relin_keys());
        rk.load(*context, rk_stream);
    }
    {
        std::istringstream gk_stream(request.galois_keys());
        gk.load(*context, gk_stream);
    }

    // Deserialize the record
    record.assign(request.record().begin(), request.record().end());

    // Deserialize the userEncryptedSymmetricKey
    for (const auto& key_str : request.user_encrypted_symmetric_key()) {
        seal::Ciphertext ct;
        std::istringstream key_stream(key_str);
        ct.load(*context, key_stream);
        userEncryptedSymmetricKey.push_back(ct);
    }

    return true;
}

bool DecompositionServer::performDecomposition() {
    // Create the PASTA_SEAL object
    pasta::PASTA_SEAL HHE(context, pk, sk, rk, gk);

    // Perform the decomposition
    result = HHE.decomposition(record, userEncryptedSymmetricKey, false);

    // Create the DecompositionResponse protobuf message
    for (const auto& ct : result) {
        std::ostringstream ct_stream;
        ct.save(ct_stream);
        response.add_he_enc_data(ct_stream.str());
    }

    return true;
}

bool DecompositionServer::serializeResponse(std::ostream& output) {
    if (!response.SerializeToOstream(&output)) {
        std::cerr << "Failed to serialize DecompositionResponse protobuf message" << std::endl;
        return false;
    }
    return true;
}

void DecompositionServer::printResult() {
    for (const auto& ct : result) {
        seal_byte* buffer = nullptr;
        int input_size = ct.save_size();
        buffer = new seal_byte[input_size];
        ct.save(buffer, input_size);
        for (int i = 0; i < 10; i++) {
            std::cout << (int)buffer[i] << ' ';
        }
        std::cout << "... ..." << std::endl;
        delete[] buffer;
    }
}

int main() {
    DecompositionServer server;

    if (!server.deserializeRequest(std::cin)) {
        return 1;
    }

    if (!server.performDecomposition()) {
        return 1;
    }

    //server.printResult();

    if (!server.serializeResponse(std::cout)) {
        return 1;
    }

    return 0;
}