#include "AnalystServiceUserClient.h"

/**
rpc service - get Analyst HE Public key
*/
int AnalystServiceUserClient::getPublicKey (seal_byte* &buffer) 
{
    Empty request;
    PublicKeyMsg reply;
    ClientContext context;
    
    // Send the request to Analyst server to obtain Analyst HE Public key
    Status status = stub_->getPublicKey(&context, request, &reply);

    if (status.ok()) 
    {  
      int pk_length = reply.length();
      buffer = new seal_byte[pk_length];

      string pk = reply.data();
      memcpy(buffer, pk.data(), pk.length());

      return pk_length;
    } 
    else 
    {
      cout << status.error_code() << ": " << status.error_message()
                << endl;
      return -1;
    }
}



