#pragma once

#include <iostream>
#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>
#include "hhe.grpc.pb.h"

#include "CSP.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using hheproto::AnalystService;
using hheproto::Empty;
using hheproto::CiphertextMsg;

class AnalystServiceCSPClient 
{
    public:
        AnalystServiceCSPClient(std::shared_ptr<Channel> channel, CSP* csp)
                    
        {
            stub_ = AnalystService::NewStub(channel);
            this->csp = csp;
        }

        bool addEncryptedResult(string analystId);


    private:
        std::unique_ptr<AnalystService::Stub> stub_;
        CSP* csp;
};
