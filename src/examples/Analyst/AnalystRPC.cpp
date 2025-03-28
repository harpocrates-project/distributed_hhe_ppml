#include "AnalystRPC.h"
#include "CSPServiceAnalystClient.h"
#include "uuid.h"

/**
rpc service - get the public key
*/
Status AnalystServiceImpl::getPublicKey(ServerContext* context, const Empty* request, PublicKeyMsg* reply)
{
    seal_byte* buffer = nullptr;

    cout << "[Analyst Service] Sending HE Public key to User"<< endl;

    // get the analyst HE Public key size
    int size = analyst->getPublicKeyBytes(buffer);

    reply->set_data(buffer, size);
    reply->set_length(size);

    return Status::OK;
} 

/**
rpc service - get the encrypted result from CSP
*/
Status AnalystServiceImpl::addEncryptedResult(ServerContext* context, const CiphertextResult* request, Empty* reply)
{
    reply = new Empty();

    cout << "[Analyst Service] Adding and decrypting the result from CSP "<< endl;

    std::string strBuffer;
    seal_byte* buffer = nullptr;
    // int length;
    vector<seal_byte*> resultsBytes;
    vector<int> resultsLengths;
   
    int len;
    for (int i=0, length; i < request->result_size(); i++)
    {
        strBuffer = request->result(i).data();
        length = request->result(i).length();

        buffer = new seal_byte[length];

        // Receive the encrypted result from CSP
        memcpy(buffer, strBuffer.data(), strBuffer.length());
        resultsBytes.push_back(buffer);
        resultsLengths.push_back(length);
        
        len = length;

        // Analyst calls decryptData() to decrypt the encrypted result
        analyst->decryptData(buffer, length);
    }
    
    //cout << "bytes size: " << resultsBytes.size() << endl;
    //cout << "lengths size: " << resultsLengths.size() << endl;

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

    // Create an instance of factory ServerBuilder class
    ServerBuilder builder;
    builder.SetMaxReceiveMessageSize(-1);

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

int main(int argc,char** argv)
{
    BaseAnalyst* analyst;
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

    // Generate uuid for analyst
    string analystUUID = uuid::generate_uuid_v4();
    cout << "Analyst's UUID: " << analystUUID << endl;

    // Create objs of analyst and analystRPC
    analyst = new Analyst_hhe_pktnn_1fc();
    analystRPC = new AnalystServiceImpl(url, analyst);

    ChannelArguments args;
    args.SetMaxSendMessageSize(-1);
    cspClient = new CSPServiceAnalystClient(grpc::CreateCustomChannel(cspUrl, grpc::InsecureChannelCredentials(), args), analyst, url);

    string dataset = "SpO2"; // dataset must be either "SpO2" or "ECG"
    analyst->setDataSet(dataset);
    analyst->generateHEKeys();  // Set up HE key 
    analyst->setEncryptor();    // Set up HE encryptor
    analyst->setDecryptor();    // set up HE decryptor

    analystRPC->runServer();    // Start Analyst server

    // For HHE_PocketNN_1FC calculation
    analyst->NNModelEncryption(analyst->getDataSet());

    // Should send public keys to cloud provider
    cspClient->addPublicKeys(analystUUID);

    // Now send encrpyted model data to cloud provider
    cspClient->addMLModel();

    // Wait for a reply in the RPC thread

    cout << "[Analyst Service] Press Enter to exit" << endl;
    std::cin.get();
    return 0;
}
