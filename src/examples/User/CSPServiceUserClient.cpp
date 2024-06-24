#include "CSPServiceUserClient.h"

bool CSPServiceUserClient::addEncryptedKeys(string analystId)
{
    EncSymmetricKeysMsg request;
    Empty reply;
    ClientContext context;

    cout << "[CSPServiceUserClient] Sending enc sym keys to CSP" << endl;

    context.AddMetadata("analystid", analystId);

    int keysNumber = user->getEncryptedSymmetricKeys().size();
    seal_byte* keyBytes;

    cout << dec << "[CSPServiceUserClient] keysNumber: " << keysNumber <<endl;

    for (int i=0, size; i<keysNumber; i++)
    {
        size = user->getEncSymmetricKeyBytes(keyBytes, i);

        cout << "[CSPServiceUserClient] key " << i << " size " << size << endl;
        hheproto::CiphertextMsg* key = request.add_key();
        key->set_data(keyBytes, size);
        key->set_length(size);
    }
    


    Status status = stub_->addEncryptedKeys(&context, request, &reply);

    if (status.ok()) {
      cout << dec << "[CSPServiceUserClient] Successfully uploaded enc sym keys to CSP" << endl;
      return true;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return false;
    }
}

bool CSPServiceUserClient::addEncryptedData(string analystId) 
{
    EncSymmetricDataMsg request;
    Empty reply;
    ClientContext context;

    cout << "[CSPServiceUserClient] Sending enc sym data to CSP" << endl;

    context.AddMetadata("analystid", analystId);

    vector<uint64_t> data = user->getEncryptedData();
    
    for (uint64_t v : data)
        request.add_value(v);

    Status status = stub_->addEncryptedData(&context, request, &reply);

    if (status.ok()) {
      cout << "[CSPServiceUserClient] Successfully uploaded enc sym data to CSP" << endl;
      return true;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return false;
    }
}