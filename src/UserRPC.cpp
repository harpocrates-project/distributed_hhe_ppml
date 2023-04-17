#include "User.h"
#include "AnalystServiceUserClient.h"
#include "CSPServiceUserClient.h"

int main(int argc, char** argv) 
{
  string analystUrl;
  string cspUrl;

  if (argc == 3)
  {
      analystUrl = argv[1];
      cspUrl = argv[2];
  }

  else if (argc != 1)
  {
      cout << "[UserRPC] Wrong number of arguments provided – using default values" << endl;
      analystUrl = "localhost:50051";
      cspUrl = "localhost:50052";
  }

  else
  {
      cout << "[UserRPC] No arguments provided – using default values" << endl;
      analystUrl = "localhost:50051";
      cspUrl = "localhost:50052";
  }

  vector<uint64_t> plaintext{0, 1, 2, 3};
  User* user = new User(plaintext);

  AnalystServiceUserClient AnalystRPCClient(
      grpc::CreateChannel(analystUrl, grpc::InsecureChannelCredentials()));

  CSPServiceUserClient CSPRPCClient(
      grpc::CreateChannel(cspUrl, grpc::InsecureChannelCredentials()), user);
  
  user->generateSymmetricKey();
  user->printData();
  user->encryptData();

  seal_byte* buffer = nullptr;
  int length = AnalystRPCClient.getPublicKey(buffer);

  /*
  for (int i = 0; i < 10; i++) {
       std::cout << (int)buffer[i] << ' ';
  }
  cout << endl;
  */

  std::cout << "[UserRPC] Received Public Key from Analyst (size=" << length << ")" << std::endl;

  user->encryptSymmetricKey(buffer, length);

  // temporary solution for the AnalystId is to use the AnalystURL
  CSPRPCClient.addEncryptedKeys(analystUrl);
  CSPRPCClient.addEncryptedData(analystUrl);

  return 0;
}
