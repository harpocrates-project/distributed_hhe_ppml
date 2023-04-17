#pragma once

#include <iostream>
#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>
#include "hhe.grpc.pb.h"

#include "Common.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using hheproto::AnalystService;
using hheproto::Empty;
using hheproto::PublicKeyMsg;

class AnalystServiceUserClient 
{
    public:
        AnalystServiceUserClient(std::shared_ptr<Channel> channel)
            : stub_(AnalystService::NewStub(channel)) { }

    int getPublicKey (seal_byte* &buffer);


    private:
        std::unique_ptr<AnalystService::Stub> stub_;
};
