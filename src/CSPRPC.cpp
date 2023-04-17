#include "CSPRPC.h"
   
Status CSPServiceImpl::addPublicKeys(ServerContext* context, const PublicKeySetMsg* request, Empty* reply)
{
    string analystId = getAnalystId(context->client_metadata());

    reply = new Empty();

    cout << "[CSP Service] adding public keys for analyst" << endl;

    std::string strBuffer;
    seal_byte* buffer = nullptr;
    int length;
   
    strBuffer = request->pk().data();
    length = request->pk().length();

    buffer = new seal_byte[length];

    std::memcpy(buffer, strBuffer.data(), strBuffer.length());
    csp->addPublicKey(analystId, buffer, length);

    strBuffer = request->rk().data();
    length = request->rk().length();

    buffer = new seal_byte[length];

    std::memcpy(buffer, strBuffer.data(), strBuffer.length());
    csp->addRelinKey(analystId, buffer, length);

    strBuffer = request->gk().data();
    length = request->gk().length();

    buffer = new seal_byte[length];

    std::memcpy(buffer, strBuffer.data(), strBuffer.length());
    csp->addGaloisKey(analystId, buffer, length);

    return Status::OK;
}


Status CSPServiceImpl::addMLModel(ServerContext* context, const MLModelMsg* request, Empty* reply)
{
    string analystId = getAnalystId(context->client_metadata());

    reply = new Empty();

    cout << "[CSP Service] adding new ML Model for analyst" << endl;

    std::string strBuffer;
    seal_byte* buffer = nullptr;
    int length;
   
    strBuffer = request->weights().data();
    length = request->weights().length();

    buffer = new seal_byte[length];

    std::memcpy(buffer, strBuffer.data(), strBuffer.length());
    csp->addEncWeights(analystId, buffer, length);

    strBuffer = request->bias().data();
    length = request->bias().length();

    buffer = new seal_byte[length];

    std::memcpy(buffer, strBuffer.data(), strBuffer.length());
    csp->addEncBias(analystId, buffer, length);

    return Status::OK;
} 


Status CSPServiceImpl::addEncryptedKeys(ServerContext* context, const EncSymmetricKeysMsg* request, Empty* reply)
{
    string analystId = getAnalystId(context->client_metadata());
 
    reply = new Empty();

    cout << "[CSP Service] adding new User Enc Sym keys for Analyst" << endl;
    
    std::string strBuffer;
    seal_byte* buffer = nullptr;

    vector<seal_byte*> keysBytes;
    vector<int> keysLengths;

    for (int i=0, length; i<request->key_size(); i++)
    {
        strBuffer = request->key(i).data();
        length = request->key(i).length();
	buffer = new seal_byte[length];
        std::memcpy(buffer, strBuffer.data(), strBuffer.length());
        keysBytes.push_back(buffer);
        keysLengths.push_back(length);
    }
    
    //cout << "bytes size: " << keysBytes.size() << endl;
    //cout << "lengths size: " << keysLengths.size() << endl;

    csp->addEncSymKeys(analystId, keysBytes, keysLengths);
    
    return Status::OK;
}


Status CSPServiceImpl::addEncryptedData(ServerContext* context, const EncSymmetricDataMsg* request, Empty* reply)
{
    string analystId = getAnalystId(context->client_metadata());

    reply = new Empty();

    cout << "[CSP Service] adding new User Enc Sym data for Analyst" << endl;

    vector<uint64_t> values(request->value().begin(), request->value().end());
    
    csp->addEncSymData(analystId, values);

    // TODO: should be done in a separate thread
    csp->decompose(analystId);
    csp->evaluateModel(analystId);

    // creates an object that is used to callback the Analyst
    AnalystServiceCSPClient* analystRPCClient = new AnalystServiceCSPClient(grpc::CreateChannel(analystId, grpc::InsecureChannelCredentials()), csp);
    analystRPCClient->addEncryptedResult(analystId);    

    return Status::OK;
}



void CSPServiceImpl::runServer()
{   
    listener = new thread(&CSPServiceImpl::startRPCService, this);
}


void CSPServiceImpl::startRPCService()
{
    grpc::EnableDefaultHealthCheckService(true);
    grpc::reflection::InitProtoReflectionServerBuilderPlugin();

    ServerBuilder builder;
    builder.SetMaxReceiveMessageSize(-1);
    // Listen on the given address without any authentication mechanism.
    builder.AddListeningPort(url, grpc::InsecureServerCredentials());
    
    // Register "service" as the instance through which we'll communicate with
    // clients. In this case it corresponds to an *synchronous* service.
    builder.RegisterService(this);

    // Finally assemble the server.
    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << endl << "[CSP Service] RPC Server listening on " << url << std::endl;

    // Wait for the server to shutdown. Note that some other thread must be
    // responsible for shutting down the server for this call to ever return.
    server->Wait();
}


string CSPServiceImpl::getAnalystId(std::multimap<grpc::string_ref, grpc::string_ref> metadata)
{
    std::multimap<grpc::string_ref, grpc::string_ref>::const_iterator metadataIterator = metadata.find("analystid");

    if (metadataIterator != metadata.end())
    {
        string analystId(metadataIterator->second.data(), metadataIterator->second.length());
        return analystId;
    }

    return "notFound";
}




int main(int argc, char** argv)
{
    CSP* csp;
    CSPServiceImpl* cspRPC;	

    string url;

    if (argc == 2)
    {
        url = argv[1];
    }

    else if (argc != 1)
    {
        cout << "[CSP Service] Wrong number of arguments provided – using default values" << endl;
        url = "localhost:50052";
    }
    else
    {
        cout << "[CSP Service] No arguments provided – using default values" << endl;
        url = "localhost:50052";
    }

    csp = new CSP();
    cspRPC = new CSPServiceImpl(url, csp);

    cspRPC->runServer();

    cout << "[CSP Service] Press Enter to exit";
    cin.get();

    return 0;     
}
