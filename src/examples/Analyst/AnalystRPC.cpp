#include "AnalystRPC.h"
#include "CSPServiceAnalystClient.h"


Status AnalystServiceImpl::getPublicKey(ServerContext* context, const Empty* request, PublicKeyMsg* reply){
    seal_byte* buffer = nullptr;
 
    cout << "[Analyst Service] Sending Public Key to the User"<< endl;

    int size = analyst->getPublicKeyBytes(buffer);

    reply->set_data(buffer, size);
    reply->set_length(size);

    return Status::OK;
} 

void AnalystServiceImpl::runServer(){
    listener = new thread(&AnalystServiceImpl::startRPCService, this);
}

void AnalystServiceImpl::startRPCService(){
    grpc::EnableDefaultHealthCheckService(true);
    grpc::reflection::InitProtoReflectionServerBuilderPlugin();

    // Create an instance of factory ServerBuilder class
    ServerBuilder builder;

    // Specify the address and port we want to use to listen for client requests using the builder’s AddListeningPort() method.
    builder.AddListeningPort(url,grpc::InsecureServerCredentials());

    // Register our service implementation with the builder.
    builder.RegisterService(this);

    // Call BuildAndStart() on the builder to create and start an RPC server for our service.
    unique_ptr<Server> server(builder.BuildAndStart());
    cout << "[Analyst Service] RCP Server listening on  " << url << endl;

    // Call Wait() on the server to do a blocking wait until process is killed or Shutdown() is called
    server->Wait();
}

int main(int argc,char** argv){
    BaseAnalyst* analyst;
    AnalystServiceImpl* analystRPC; 
    CSPServiceAnalystClient* cspClient;	

    string url;
    string cspUrl;

    if (argc == 3){
        url = argv[1];
        cspUrl = argv[2];
    } else if (argc != 1){
        cout << "[Analyst Service] Wrong number of arguments provided – using default values" << endl;
        url = "localhost:50051";
        cspUrl = "localhost:50052";
    } else {
        cout << "[Analyst Service] Wrong number of arguments provided – using default values" << endl;
        url = "localhost:50051";
        cspUrl = "localhost:50052";
    }

    analyst = new Analyst_hhe_pktnn_1fc();
    analystRPC = new AnalystServiceImpl(url, analyst);

    ChannelArguments args;
    args.SetMaxSendMessageSize(-1);
    cspClient = new CSPServiceAnalystClient(grpc::CreateCustomChannel(cspUrl, grpc::InsecureChannelCredentials(), args), analyst, url);

    analyst->generateHEKeys();
    analystRPC->runServer();   

    analyst->setEncryptor();
    analyst->setDecryptor();
    analyst->func(
        analyst->getAnalystHePublicKey(),
        analyst->getBatchEncoder(),
        analyst->getEncryptor(),
        analyst->getDecryptor()
    );

    // should send public keys to cloud provider
    cspClient->addPublicKeys();

    cout << "[Analyst Service] Press Enter to exit" << endl;
    std::cin.get();
    return 0;
}
