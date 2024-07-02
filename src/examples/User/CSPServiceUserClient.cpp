#include "CSPServiceUserClient.h"

/**
rpc service - Send the encrypted symmetic key to CSP
*/
bool CSPServiceUserClient::addEncryptedKeys(string analystId)
{
    EncSymmetricKeysMsg request;
    Empty reply;
    ClientContext context;

    cout << "[CSPServiceUserClient] Sending encrypted symmetric key to CSP" << endl;

    context.AddMetadata("analystid", analystId);

    // get the encrypted symmetic key length
    int keysNumber = user->getEncryptedSymmetricKey().size();
 
    seal_byte* keyBytes;

    // cout << "[CSPServiceUserClient] keysNumber: " << keysNumber <<endl;

    for (int i=0, size; i<keysNumber; i++)
    {
        // get the encrypted symmetric key bytes
        size = user->getEncryptedSymmetricKeyBytes(keyBytes, i);

        // cout << "[CSPServiceUserClient] key " << i << " size " << size << endl;
        hheproto::CiphertextMsg* key = request.add_key();
        key->set_data(keyBytes, size);
        key->set_length(size);
    }

    // Send the encrypted symmetric key to CSP
    Status status = stub_->addEncryptedKeys(&context, request, &reply);

    if (status.ok()) 
    {
      cout << dec << "[CSPServiceUserClient] Successfully uploaded encrypted symmetric key to CSP" << endl;
      return true;
    } 
    else 
    {
      cout << status.error_code() << ": " << status.error_message() << endl;
      return false;
    }
}

/**
rpc service - Send the encrypted data to CSP
*/
bool CSPServiceUserClient::addEncryptedData(string analystId) 
{
    EncSymmetricDataMsg request;
    Empty reply;
    ClientContext context;

    cout << "[CSPServiceUserClient] Sending encrypted data to CSP" << endl;

    context.AddMetadata("analystid", analystId);

    // get the encrypted data
    vector<uint64_t> data = user->getEncryptedData();   
    
    for (uint64_t v : data)
        request.add_value(v);

    // Send the encrypted data to CSP
    Status status = stub_->addEncryptedData(&context, request, &reply);
    
    if (status.ok()) 
    {
      cout << "[CSPServiceUserClient] Successfully uploaded encrypted data to CSP" << endl;
      return true;
    } 
    else 
    {
      cout << status.error_code() << ": " << status.error_message() << endl;
      return false;
    }
}