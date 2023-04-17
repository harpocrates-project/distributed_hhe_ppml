#pragma once

#include <iostream>
#include <memory>
#include <string>
#include <map>

#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>

#include "hhe.grpc.pb.h"

#include "CSP.h"
#include "AnalystServiceCSPClient.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using hheproto::CSPService;
using hheproto::Empty;
using hheproto::PublicKeySetMsg;
using hheproto::MLModelMsg;
using hheproto::EncSymmetricKeysMsg;
using hheproto::EncSymmetricDataMsg;


class CSPServiceImpl final : public CSPService::Service 
{
  private:
  	CSP* csp;
  	string url; 

        thread* listener;
 
        void startRPCService();
        string getAnalystId(std::multimap<grpc::string_ref, grpc::string_ref> metadata);

  public:
    	CSPServiceImpl(string url, CSP* csp)
    	{
	    this->url = url;
      	    this->csp = csp;
        } 
   
        Status addPublicKeys(ServerContext* context, const PublicKeySetMsg* request, Empty* reply) override;
        Status addMLModel(ServerContext* context, const MLModelMsg* request, Empty* reply) override;
        Status addEncryptedKeys(ServerContext* context, const EncSymmetricKeysMsg* request, Empty* reply) override;
        Status addEncryptedData(ServerContext* context, const EncSymmetricDataMsg* request, Empty* reply) override;

	void runServer();
	void stopServer();
};
