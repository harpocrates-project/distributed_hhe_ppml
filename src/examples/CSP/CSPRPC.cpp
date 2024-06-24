#include "CSPRPC.h"

Status CSPServiceImpl::addPublicKeys(ServerContext* context, const PublicKeySetMsg* request, Empty* reply)
{
    string analystId = getAnalystId(context->client_metadata());

    reply = new Empty();

    cout << "[CSP Service] adding public keys for analyst" << endl;

    std::string strBuffer;
    seal_byte* buffer = nullptr;
    int length;
   
    // Analyst HE Public key
    strBuffer = request->pk().data();
    length = request->pk().length();
 
    buffer = new seal_byte[length];

    std::memcpy(buffer, strBuffer.data(), strBuffer.length());
    csp->addPublicKey(analystId, buffer, length);

    // Analyst HE Relin key
    strBuffer = request->rk().data();
    length = request->rk().length();
   
    buffer = new seal_byte[length];

    std::memcpy(buffer, strBuffer.data(), strBuffer.length());
    csp->addRelinKey(analystId, buffer, length);

    // Analyst Galois key
    strBuffer = request->gk().data();
    length = request->gk().length();
    
    buffer = new seal_byte[length];

    std::memcpy(buffer, strBuffer.data(), strBuffer.length());
    csp->addGaloisKey(analystId, buffer, length);

    // Analyst HE Secret key
    strBuffer = request->sk().data();
    length = request->sk().length();
 
    buffer = new seal_byte[length];

    std::memcpy(buffer, strBuffer.data(), strBuffer.length());
    csp->addSecretKey(analystId, buffer, length);

    return Status::OK;
}


Status CSPServiceImpl::addMLModel(ServerContext* context, const MLModelMsg* request, Empty* reply)
{
    string analystId = getAnalystId(context->client_metadata());

    reply = new Empty();

    cout << "[CSP Service] adding new ML Model for analyst" << endl;

    std::string strBuffer;
    seal_byte* buffer = nullptr;
    
    vector<seal_byte*> wBytes;
    vector<int> wLengths;


    for (int i=0, length; i<request->weights_size(); i++)
    {
        strBuffer = request->weights(i).data();
        length = request->weights(i).length();
	    buffer = new seal_byte[length];
        std::memcpy(buffer, strBuffer.data(), strBuffer.length());
        wBytes.push_back(buffer);
        wLengths.push_back(length);

        cout << "weights length: " << length << endl;
    }

    cout<<"[CSP Service] Analyst's encrypted weights" << endl;
    for (int i = 0; i < 10; i++) {
        std::cout << (int)buffer[i] << ' ';
    }
    cout << endl;

    // cout<<"[CSP Service] weights size"<< request->weights_size()<< endl;
    csp->addEncWeights(analystId, wBytes, wLengths);
    
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

    cout << "[CSP Service] keysNumbers: " << request->key_size() << endl;
    for (int i=0, length; i<request->key_size(); i++)
    {
        strBuffer = request->key(i).data();
        length = request->key(i).length();
	    buffer = new seal_byte[length];
        std::memcpy(buffer, strBuffer.data(), strBuffer.length());
        keysBytes.push_back(buffer);
        keysLengths.push_back(length);

        cout<<"[CSP Service] User's encrypted symmetric key length: " << length << endl;
    }
    
    cout<<"[CSP Service] User's encrypted symmetric key"<<endl;
    for (int i = 0; i < 10; i++) {
        std::cout << (int)buffer[i] << ' ';
    }
    cout << endl;

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
    
    cout << "[CSP Service] encrypted data via symmetric key algorithm" << endl;   
    utils::print_vec(values, values.size(), "vi_se");
    cout << "User's encrypted data size: " << values.size() << endl;

    csp->addEncSymData(analystId, values); 

    // TODO: should be done in a separate thread
    csp->decompose(analystId);
    // csp->evaluateModel(analystId);

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


int main(int argc,char** argv){
    BaseCSP* csp;
    CSPServiceImpl* cspRPC;	

    string url;

    if (argc == 2){
        url = argv[1];
    } else if (argc != 1) {
        cout << "[CSP Service] Wrong number of arguments provided – using default values" << endl;
        url = "localhost:50052";
    } else {
        cout << "[CSP Service] No arguments provided – using default values" << endl;
        url = "localhost:50052";
    }

    csp = new BaseCSP();
    cspRPC = new CSPServiceImpl(url, csp);

    csp->heInitialization();   
    
    cspRPC->runServer();

    cout << "[CSP Service] Press Enter to exit";
    cin.get();

    return 0;
}