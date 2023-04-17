#pragma once

#include <iostream>
#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>
#include "hhe.grpc.pb.h"

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

        CSPServiceAnalystClient(std::shared_ptr<Channel> channel, Analyst* a, string analystURL)
        {
            stub_ = CSPService::NewStub(channel);
            analyst = a;
            analystId = analystURL;
        }

        bool addPublicKeys();
        bool addMLModel(); 

    private:
        Analyst* analyst;
        string analystId;
        std::unique_ptr<CSPService::Stub> stub_;
};
