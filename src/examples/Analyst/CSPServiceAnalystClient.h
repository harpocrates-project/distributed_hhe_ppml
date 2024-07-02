#pragma once

#include <iostream>
#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>
#include "../../gen_code/hhe.grpc.pb.h"

#include "Analyst.h"


using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using grpc::ChannelArguments;

using hheproto::CSPService;
using hheproto::Empty;
using hheproto::PublicKeySetMsg;
using hheproto::MLModelMsg;


class CSPServiceAnalystClient
{
    public:
        CSPServiceAnalystClient(shared_ptr<Channel> channel, BaseAnalyst* a, string analystURL)
        {
            stub_ = CSPService::NewStub(channel);
            analyst = a;
            analystId = analystURL;
        }

        /**
        rpc service - Send HE Public keys to CSP
        */
        bool addPublicKeys();
        
        /** 
        rpc service - Send NN encrypted params to CSP
        */
        bool addMLModel(); 

    private:
        BaseAnalyst* analyst;
        string analystId;
        unique_ptr<CSPService::Stub> stub_;
};