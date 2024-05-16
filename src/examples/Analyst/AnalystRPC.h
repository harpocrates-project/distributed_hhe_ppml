#pragma

#include <iostream>
#include <memory>
#include <string>

#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>

#include "../../gen_code/hhe.grpc.pb.h"

#include "Analyst.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerReader;
using grpc::ServerWriter;
using grpc::ServerReaderWriter;
using grpc::Status;

using hheproto::AnalystService;
using hheproto::Empty;
using hheproto::PublicKeyMsg;

using namespace hheproto;
using namespace std;


class AnalystServiceImpl final:public AnalystService::Service{
    public:
        AnalystServiceImpl(string url, BaseAnalyst* a){
            this->url = url;
            analyst = a;
        }

        Status getPublicKey(ServerContext* context, const Empty* request, PublicKeyMsg* reply) override; 

        void runServer();
        void stopServer();

    private:
        BaseAnalyst* analyst;
        string url;

        thread* listener;

        void startRPCService();
};
