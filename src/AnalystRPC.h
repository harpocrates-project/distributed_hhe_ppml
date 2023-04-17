#pragma once

#include <iostream>
#include <memory>
#include <string>

#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>

#include "hhe.grpc.pb.h"

#include "Analyst.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using hheproto::AnalystService;
using hheproto::Empty;
using hheproto::PublicKeyMsg;
using hheproto::CiphertextMsg;


class AnalystServiceImpl final : public AnalystService::Service 
{
  private:
  	Analyst* analyst;
  	string url; 

        thread* listener;

        void startRPCService();

  public:
    	AnalystServiceImpl(string url, Analyst* a)
    	{
	    this->url = url;
      	    analyst = a;
        } 
    
        Status getPublicKey(ServerContext* context, const Empty* request, PublicKeyMsg* reply) override; 
        Status addEncryptedResult(ServerContext* context, const CiphertextMsg* request, Empty* reply) override;     
 
	void runServer();
	void stopServer();

};
