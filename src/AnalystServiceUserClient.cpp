#include "AnalystServiceUserClient.h"

int AnalystServiceUserClient::getPublicKey (seal_byte* &buffer) 
{
    Empty request;

    PublicKeyMsg reply;

    ClientContext context;
    
    Status status = stub_->getPublicKey(&context, request, &reply);

    if (status.ok()) 
    {  
      int pk_length = reply.length();
      buffer = new seal_byte[pk_length];

      std::string pk = reply.data();
      std::memcpy(buffer, pk.data(), pk.length());

      return pk_length;
    } 

    else 
    {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return -1;
    }
}


