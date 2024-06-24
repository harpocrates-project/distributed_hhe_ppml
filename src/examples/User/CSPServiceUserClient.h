#pragma once

#include <iostream>
#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>
#include "../../gen_code/hhe.grpc.pb.h"

#include "User.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using grpc::ChannelArguments;
using hheproto::CSPService;
using hheproto::Empty;
using hheproto::EncSymmetricKeysMsg;
using hheproto::EncSymmetricDataMsg;


class CSPServiceUserClient 
{

    public:

        CSPServiceUserClient(std::shared_ptr<Channel> channel, User* u)
        {
            stub_ = CSPService::NewStub(channel);
            user = u;
        }

        bool addEncryptedKeys(string analystId);
        bool addEncryptedData(string analystId); 

    private:
        User* user;
        std::unique_ptr<CSPService::Stub> stub_;
};