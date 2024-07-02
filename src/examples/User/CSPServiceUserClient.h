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

        CSPServiceUserClient(shared_ptr<Channel> channel, User* u)
        {
            stub_ = CSPService::NewStub(channel);
            user = u;
        }

        /**
        rpc service - Send the encrypted symmetic key to CSP
        */
        bool addEncryptedKeys(string analystId);

        /**
        rpc service - Send the encrypted data to CSP
        */
        bool addEncryptedData(string analystId); 

    private:
        User* user;
        unique_ptr<CSPService::Stub> stub_;
};