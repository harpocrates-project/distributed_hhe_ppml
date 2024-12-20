#pragma once

#include <iostream>
#include <memory>
#include <string>
#include <map>

#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>

#include "../../gen_code/hhe.grpc.pb.h"

#include "CSP.h"
#include "AnalystServiceCSPClient.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

using hheproto::CSPService;
using hheproto::Empty;
using hheproto::PublicKeySetMsg;
using hheproto::EncSymmetricKeysMsg;
using hheproto::EncSymmetricDataMsg;
using hheproto::EncSymmetricDataRecord;
using hheproto::MLModelMsg;
using hheproto::CiphertextBytes;


class CSPServiceImpl final:public CSPService::Service
{ 
    public:
        CSPServiceImpl(string url, BaseCSP* csp)
        {
            this->url = url;
            this->csp = csp;
        }

        /** 
        rpc service - Add HE Public keys
        */
        Status addPublicKeys(ServerContext* context, const PublicKeySetMsg* request, Empty* reply) override;
        
        /**
        rpc service - Add User encrypted symmetric key
        */
        Status addEncryptedKeys(ServerContext* context, const EncSymmetricKeysMsg* request, Empty* reply) override;
        
        /**
        rpc service - Add User encrypted data for NN calculation
        */
        Status addEncryptedData(ServerContext* context, const EncSymmetricDataMsg* request, Empty* reply) override;
       
        /**
        rpc service - Add NN encrypted params (weights)
        */
        Status addMLModel(ServerContext* context, const MLModelMsg* request, Empty* reply) override;

        /**
        rpc service - Receive data and evaluate date under NN model
        */
        Status evaluateModel(ServerContext* context, const CiphertextBytes* request, Empty* reply) override;
        
        void runServer();

    private:
        BaseCSP* csp;
  	    string url; 
        thread* listener;
 
        void startRPCService();
        
        vector <vector<uint64_t>> values;

        /**
        Get Analyst IP Addr
        */
        string getAnalystId(multimap<grpc::string_ref, grpc::string_ref> metadata);
};

