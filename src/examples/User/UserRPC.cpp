#include "AnalystServiceUserClient.h"
#include "CSPServiceUserClient.h"
#include "User.h"


int main(int argc,char** argv)
{
    string analystUrl;
    string cspUrl;

    if (argc == 3) {
        analystUrl = argv[1];
        cspUrl = argv[2];
    } else if (argc != 1) {
        cout << "[UserRPC] Wrong number of arguments provided – using default values" << endl;
        analystUrl = "localhost:50051";
        cspUrl = "localhost:50052";
    } else {
        cout << "[UserRPC] No arguments provided – using default values" << endl;
        analystUrl = "localhost:50051";
        cspUrl = "localhost:50052";
    }
    
    User* user = new User();

    // create a gRPC channel for our stub
    //grpc::CreateChannel("locakhost:50051",grpc::InsecureChannelCredentials());
    AnalystServiceUserClient AnalystRPCClient(
      grpc::CreateChannel(analystUrl, grpc::InsecureChannelCredentials()));

    CSPServiceUserClient CSPRPCClient(
      grpc::CreateChannel(cspUrl, grpc::InsecureChannelCredentials()), user);  

   
    cout<<"=============================="<<endl;
    user->loadDataAndLabel();
    // Create user's symmetric key which will be used for data encryption;
    user->setUserSymmetricKey();
    // Encrypt user data via symmetric key algorithm
    user->encryptData(
        user->getUserSymmetricKey());

    cout << "=====================" << endl;
    // Receive analyst's HE_pk  
    seal_byte* buffer = nullptr;
    int length = AnalystRPCClient.getPublicKey(buffer);
    
    for (int i = 0; i < 10; i++) {
        cout << (int)buffer[i] << ' ';
    }
    cout << endl;
    
    cout << "[UserRPC] Received Public Key from Analyst (size=" << length << ")" << endl;

    //  Encrypt user symmetric key via HE
    user->encryptSymmetricKey(user->getUserSymmetricKey(), buffer, length);

    // (Check) Computing in plain on 1 input vector
    user->computingCheck();

    // User sends his encrypted symmetric key to the csp
    CSPRPCClient.addEncryptedKeys(analystUrl);
    // User sends his encrypted data to the csp
    CSPRPCClient.addEncryptedData(analystUrl);

   return 0;
}