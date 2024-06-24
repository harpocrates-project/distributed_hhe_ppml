#include "CSPServiceAnalystClient.h"

bool CSPServiceAnalystClient::addPublicKeys() 
{
    PublicKeySetMsg request;
    Empty reply;
    ClientContext context;

    cout << dec << "[CSPServiceAnalystClient] Sending HE keys to CSP" << endl;

    context.AddMetadata("analystid", analystId); 

    // HE Public Key
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

    
    // HE Relin Key 
    size = analyst->getRelinKeysBytes(buffer);

    /*
    for (int i = 0; i < 10; i++) {
        std::cout << (int)buffer[i] << ' ';
    }
    cout << endl;
    */

    request.mutable_rk()->set_data(buffer, size);
    request.mutable_rk()->set_length(size);


    // HE Galois Key
    size = analyst->getGaloisKeysBytes(buffer);

    /*
    for (int i = 0; i < 10; i++) {
        std::cout << (int)buffer[i] << ' ';
    }
    cout << dec << endl;
    */

    request.mutable_gk()->set_data(buffer, size);
    request.mutable_gk()->set_length(size);


    // HE Secret Key
    size = analyst->getSecretKeyBytes(buffer);

    /*
    for (int i = 0; i < 10; i++) {
        std::cout << (int)buffer[i] << ' ';
    }
    cout << dec << endl;
    */

    request.mutable_sk()->set_data(buffer, size);
    request.mutable_sk()->set_length(size);


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
                           
    int wNumber = analyst->getEncryptedWeights().size();
    seal_byte* wBytes;

    // cout << dec << "[CSPServiceAnalystClient] wNumber: " << wNumber<< endl;


    for (int i=0, size; i<wNumber; i++)
    {
        size = analyst->getEncWeightsBytes(wBytes, i);

        //cout << "[CSPServiceAnalystClient] Weights " << i << " size " << size << endl;
        hheproto::CiphertextMsg* weights = request.add_weights();
        weights->set_data(wBytes, size);
        weights->set_length(size);
    }

    cout<<"[CSPServiceAnalystClient] Analyst's encrypted weights"<<endl;
    for (int i = 0; i < 10; i++) {
        std::cout << (int)wBytes[i] << ' ';
    }
    cout << endl;

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
