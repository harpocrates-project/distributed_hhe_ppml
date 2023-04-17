#include "AnalystServiceCSPClient.h"

bool AnalystServiceCSPClient::addEncryptedResult(string analystId) 
{
    CiphertextMsg request;
    Empty reply;

    ClientContext context;
    
    cout << "[AnalystServiceCSPClient] Sending encrypted results to the Analyst (Analyst Id: " << analystId << ")" << endl;

    seal_byte* buffer = nullptr;
    int size = csp->getEncryptedResultBytes(analystId, buffer);

    /*
    for (int i = 0; i < 10; i++) {
        std::cout << (int)buffer[i] << ' ';
    }
    cout << endl;
    */

    request.set_data(buffer, size);
    request.set_length(size);

    Status status = stub_->addEncryptedResult(&context, request, &reply);

    if (status.ok()) 
    {
      cout << "[AnalystServiceCSPClient] Successfully sent encrypted results to the Analyst (Analyst Id: " << analystId << ")" << endl;
      return true;
    } 

    else 
    {
      return false;
    }
}
