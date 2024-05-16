#include "AnalystServiceUserClient.h"
#include "User.h"


int main(int argc,char** argv)
{

    string analystUrl = "localhost:50051";
    // create a gRPC channel for our stub
    //grpc::CreateChannel("locakhost:50051",grpc::InsecureChannelCredentials());
    AnalystServiceUserClient AnalystRPCClient(
      grpc::CreateChannel(analystUrl, grpc::InsecureChannelCredentials()));

    cout << "=====================" << endl;
    
    seal_byte* buffer = nullptr;
  
    int length = AnalystRPCClient.getPublicKey(buffer);

    
    for (int i = 0; i < 10; i++) {
        cout << (int)buffer[i] << ' ';
    }
    cout << endl;
    

    cout << "[UserRPC] Received Public Key from Analyst (size=" << length << ")" << endl;


    cout<<"=============================="<<endl;
    User* user = new User();
    user->loadDataAndLabel();
    // Create user's symmetric key which will be used for data encryption;
    user->setUserSymmetricKey();
    user->encryptData(
        user->getUserSymmetricKey()
    );
    return 0;
}