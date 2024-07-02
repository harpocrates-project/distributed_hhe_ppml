#include "AnalystServiceCSPClient.h"

/**
rpc service - Send encrypted result to Analyst
*/
bool AnalystServiceCSPClient::addEncryptedResult(string analystId) 
{
    CiphertextMsg request;
    Empty reply;
    ClientContext context;
    
    cout << "[AnalystServiceCSPClient] Sending the encrypted result to Analyst (AnalystId: " << analystId << ")" << endl;

    seal_byte* buffer = nullptr;
    // Get the encrypted result bytes
    int size = csp->getEncryptedResultBytes(analystId, buffer);
    
    /*for (int i = 0; i < 10; i++) 
    {
        std::cout << (int)buffer[i] << ' ';
    }
    cout << endl;*/

    request.set_data(buffer, size);
    request.set_length(size);

    // Send the encrypted result to Analyst
    Status status = stub_->addEncryptedResult(&context, request, &reply);

    if (status.ok()) 
    {
      cout << "[AnalystServiceCSPClient] Successfully sent the encrypted result to Analyst (AnalystId: " << analystId << ")" << endl;
      return true;
    } 
    else 
    {
      return false;
    }
}