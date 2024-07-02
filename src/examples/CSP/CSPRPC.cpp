#include "CSPRPC.h"

/** 
rpc service - Add HE Public keys
*/
Status CSPServiceImpl::addPublicKeys(ServerContext* context, const PublicKeySetMsg* request, Empty* reply)
{
    string analystId = getAnalystId(context->client_metadata());

    reply = new Empty();

    cout << "[CSP Service] Adding Analyst HE keys" << endl;

    string strBuffer;
    seal_byte* buffer = nullptr;
    int length;
   
    // Analyst HE Public key
    strBuffer = request->pk().data();
    length = request->pk().length();

    buffer = new seal_byte[length];

    memcpy(buffer, strBuffer.data(), strBuffer.length());
    csp->addAnalystHEPublicKey(analystId, buffer, length);

    // Analyst HE Relins key
    strBuffer = request->rk().data();
    length = request->rk().length();
   
    buffer = new seal_byte[length];

    memcpy(buffer, strBuffer.data(), strBuffer.length());
    csp->addAnalystHERelinKeys(analystId, buffer, length);

    // Analyst Galois key
    strBuffer = request->gk().data();
    length = request->gk().length();

    buffer = new seal_byte[length];

    memcpy(buffer, strBuffer.data(), strBuffer.length());
    csp->addAnalystHEGaloisKeys(analystId, buffer, length);

    // CSP HE Relins key
    strBuffer = request->csp_rk().data();
    length = request->csp_rk().length();
   
    buffer = new seal_byte[length];

    memcpy(buffer, strBuffer.data(), strBuffer.length());
    csp->addHERelinKeys(analystId, buffer, length);

    // CSP HE Galois key
    strBuffer = request->csp_gk().data();
    length = request->csp_gk().length();
    
    buffer = new seal_byte[length];

    memcpy(buffer, strBuffer.data(), strBuffer.length());
    csp->addHEGaloisKeys(analystId, buffer, length);

    return Status::OK;
}

/**
rpc service - Add NN encrypted params (weights)
*/
Status CSPServiceImpl::addMLModel(ServerContext* context, const MLModelMsg* request, Empty* reply)
{
    string analystId = getAnalystId(context->client_metadata());

    reply = new Empty();

    cout << "[CSP Service] Adding Analyst ML model" << endl;

    string strBuffer;
    seal_byte* buffer = nullptr;
    
    vector<seal_byte*> wBytes;
    vector<int> wLengths;

    int len;
    for (int i=0, length; i<request->weights_size(); i++)
    {
        strBuffer = request->weights(i).data();
        length = request->weights(i).length();
	    buffer = new seal_byte[length];
        memcpy(buffer, strBuffer.data(), strBuffer.length());
        wBytes.push_back(buffer);
        wLengths.push_back(length);
        len = length;
    }

    cout<<"[CSP Service] ML model encrypted weights and size (" << len << ")" << endl;
    for (int i = 0; i < 10; i++) 
    {
        cout << (int)buffer[i] << ' ';
    }
    cout << "... ..." << endl;

    csp->addAnalystEncryptedWeights(analystId, wBytes, wLengths);
    
    return Status::OK;
} 

/**
rpc service - Add User encrypted symmetric key
*/
Status CSPServiceImpl::addEncryptedKeys(ServerContext* context, const EncSymmetricKeysMsg* request, Empty* reply)
{
    string analystId = getAnalystId(context->client_metadata());
 
    reply = new Empty();

    cout << "[CSP Service] Adding User encrypted symmetric key" << endl;
    
    string strBuffer;
    seal_byte* buffer = nullptr;

    vector<seal_byte*> keysBytes;
    vector<int> keysLengths;

    int len;
    for (int i=0, length; i<request->key_size(); i++)
    {
        strBuffer = request->key(i).data();
        length = request->key(i).length();
	    buffer = new seal_byte[length];
        memcpy(buffer, strBuffer.data(), strBuffer.length());
        keysBytes.push_back(buffer);
        keysLengths.push_back(length);

        len = length;
    }
    
    cout<<"[CSP Service] User's encrypted symmetric key and size (" << len << ")" << endl;;
    for (int i = 0; i < 10; i++) 
    {
        cout << (int)buffer[i] << ' ';
    }
    cout << "... ..." << endl;

    //cout << "bytes size: " << keysBytes.size() << endl;
    //cout << "lengths size: " << keysLengths.size() << endl;

    csp->addUserEncryptedSymmetricKey(analystId, keysBytes, keysLengths);
    
    return Status::OK;
}

/**
rpc service - Add User encrypted data for NN calculation
*/
Status CSPServiceImpl::addEncryptedData(ServerContext* context, const EncSymmetricDataMsg* request, Empty* reply)
{
    string analystId = getAnalystId(context->client_metadata());

    reply = new Empty();

    cout << "[CSP Service] Adding User encrypted data" << endl;
    vector<uint64_t> values(request->value().begin(), request->value().end());
    utils::print_vec(values, values.size(), "vi_se"); //vi_se
    
    csp->addUserEncryptedData(analystId, values); 
  
    // TODO: should be done in a separate thread
    csp->decompose(analystId);
    csp->evaluateModel(analystId);

    // creates an object that is used to callback the Analyst
    AnalystServiceCSPClient* analystRPCClient = new AnalystServiceCSPClient(grpc::CreateChannel(analystId, grpc::InsecureChannelCredentials()), csp);
    analystRPCClient->addEncryptedResult(analystId);    

    return Status::OK;
}

/**
Get Analyst IP Addr
*/
string CSPServiceImpl::getAnalystId(multimap<grpc::string_ref, grpc::string_ref> metadata)
{
    multimap<grpc::string_ref, grpc::string_ref>::const_iterator metadataIterator = metadata.find("analystid");

    if (metadataIterator != metadata.end())
    {
        string analystId(metadataIterator->second.data(), metadataIterator->second.length());
        return analystId;
    }

    return "notFound";
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
    unique_ptr<Server> server(builder.BuildAndStart());
    cout << endl << "[CSP Service] RPC Server listening on " << url << endl;

    // Wait for the server to shutdown. Note that some other thread must be
    // responsible for shutting down the server for this call to ever return.
    server->Wait();
}

int main(int argc,char** argv)
{
    BaseCSP* csp;
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

    csp = new BaseCSP();
    cspRPC = new CSPServiceImpl(url, csp);

    // Set up HE params
    csp->hEInitialization();   
    
    // Start the csp rpc service
    cspRPC->runServer();

    cout << "[CSP Service] Press Enter to exit";
    cin.get();

    return 0;
}