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


class CSPServiceAnalystClient{
    public:
        CSPServiceAnalystClient(std::shared_ptr<Channel> channel, BaseAnalyst* a, string analystURL)
        {
            stub_ = CSPService::NewStub(channel);
            analyst = a;
            analystId = analystURL;
        }

        bool addPublicKeys();

    private:
        BaseAnalyst* analyst;
        string analystId;
        std::unique_ptr<CSPService::Stub> stub_;
};