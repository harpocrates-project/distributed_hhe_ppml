#include "CSPServiceAnalystClient.h"

bool CSPServiceAnalystClient::addPublicKeys() 
{
    PublicKeySetMsg request;
    Empty reply;
    ClientContext context;

    cout << dec << "[CSPServiceAnalystClient] Sending HE keys to CSP" << endl;

    context.AddMetadata("analystid", analystId);

    seal_byte* buffer = nullptr;
    int size = analyst->getPublicKeyBytes(buffer);

    /*
    for (int i = 0; i < 10; i++) {
        std::cout << (int)buffer[i] << ' ';
    }
    cout << endl;
    */

    request.mutable_pk()->set_data(buffer, size);
    request.mutable_pk()->set_length(size);

    
    size = analyst->getRelinKeysBytes(buffer);

    /*
    for (int i = 0; i < 10; i++) {
        std::cout << (int)buffer[i] << ' ';
    }
    cout << endl;
    */

    request.mutable_rk()->set_data(buffer, size);
    request.mutable_rk()->set_length(size);


    size = analyst->getGaloisKeysBytes(buffer);

    /*
    for (int i = 0; i < 10; i++) {
        std::cout << (int)buffer[i] << ' ';
    }
    cout << dec << endl;
    */

    request.mutable_gk()->set_data(buffer, size);
    request.mutable_gk()->set_length(size);
    

    Status status = stub_->addPublicKeys(&context, request, &reply);

    if (status.ok()) {
      cout << dec << "[CSPServiceAnalystClient] Successfully uploaded keys to CSP" << endl;
      return true;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return false;
    }
}

bool CSPServiceAnalystClient::addMLModel() 
{
    MLModelMsg request;
    Empty reply;
    ClientContext context;

    cout << dec << "[CSPServiceAnalystClient] Sending ML Model to CSP" << endl;

    context.AddMetadata("analystid", analystId);

    seal_byte* buffer = nullptr;
    int size = analyst->getEncWeightsBytes(buffer);

    /*
    for (int i = 0; i < 10; i++) {
        std::cout << (int)buffer[i] << ' ';
    }
    cout << endl;
    */

    request.mutable_weights()->set_data(buffer, size);
    request.mutable_weights()->set_length(size);

    size = analyst->getEncBiasBytes(buffer);

    request.mutable_bias()->set_data(buffer, size);
    request.mutable_bias()->set_length(size);

    Status status = stub_->addMLModel(&context, request, &reply);

    if (status.ok()) {
      cout << dec << "[CSPServiceAnalystClient] Successfully uploaded ML Model to CSP" << endl;
      return true;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return false;
    }
}
