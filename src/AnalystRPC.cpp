#include "AnalystRPC.h"
#include "CSPServiceAnalystClient.h"
   
Status AnalystServiceImpl::getPublicKey(ServerContext* context, const Empty* request, PublicKeyMsg* reply) 
{
    seal_byte* buffer = nullptr;
 
    cout << "[Analyst Service] Sending Public Key to the User"<< endl;

    int size = analyst->getPublicKeyBytes(buffer);

    /*
    for (int i = 0; i < 10; i++) {
        std::cout << (int)buffer[i] << ' ';
    }
    cout << endl;
    */

    reply->set_data(buffer, size);
    reply->set_length(size);

    return Status::OK;
}


Status AnalystServiceImpl::addEncryptedResult(ServerContext* context, const CiphertextMsg* request, Empty* reply)
{
    reply = new Empty();

    cout << "[Analyst Service] Adding and Decrypting Result from CSP "<< endl;

    std::string strBuffer;
    seal_byte* buffer = nullptr;
    int length;
   
    strBuffer = request->data();
    length = request->length();

    buffer = new seal_byte[length];

    std::memcpy(buffer, strBuffer.data(), strBuffer.length());
    analyst->decryptData(buffer, length);

    return Status::OK;
} 


void AnalystServiceImpl::runServer() 
{   
    listener = new thread(&AnalystServiceImpl::startRPCService, this);
}


void AnalystServiceImpl::startRPCService()
{
    grpc::EnableDefaultHealthCheckService(true);
    grpc::reflection::InitProtoReflectionServerBuilderPlugin();

    ServerBuilder builder;
    // Listen on the given address without any authentication mechanism.
    builder.AddListeningPort(url, grpc::InsecureServerCredentials());
    
    // Register "service" as the instance through which we'll communicate with
    // clients. In this case it corresponds to an *synchronous* service.
    builder.RegisterService(this);

    // Finally assemble the server.
    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << "[Analyst Service] RCP Server listening on " << url  << std::endl;

    // Wait for the server to shutdown. Note that some other thread must be
    // responsible for shutting down the server for this call to ever return.
    server->Wait();
} 




int main(int argc, char** argv)
{ 
    Analyst* analyst;
    AnalystServiceImpl* analystRPC;
    CSPServiceAnalystClient* cspClient;	

    string url;
    string cspUrl;

    if (argc == 3)
    {
        url = argv[1];
        cspUrl = argv[2];
    }

    else if (argc != 1)
    {
        cout << "[Analyst Service] Wrong number of arguments provided – using default values" << endl;
        url = "localhost:50051";
        cspUrl = "localhost:50052";

    }

    else
    {
        cout << "[Analyst Service] Wrong number of arguments provided – using default values" << endl;
        url = "localhost:50051";
        cspUrl = "localhost:50052";
    }

    vector<int64_t> w{17, 31, 24, 17};
    vector<int64_t> b{-5, -5, -5, -5};

    analyst = new Analyst(w, b);
    analystRPC = new AnalystServiceImpl(url, analyst);

    ChannelArguments args;
    args.SetMaxSendMessageSize(-1);
    cspClient = new CSPServiceAnalystClient(grpc::CreateCustomChannel(cspUrl, grpc::InsecureChannelCredentials(), args), analyst, url);

    analyst->generateHEKeys();
    analystRPC->runServer();
    
    // should send public keys to cloud provider
    cspClient->addPublicKeys();

    analyst->encryptData();

    // now send encrpyted model data to cloud provider
    cspClient->addMLModel();

    // wait for a reply in the RPC thread

    cout << "[Analyst Service] Press Enter to exit" << endl;
    cin.get();
    return 0;     
}
