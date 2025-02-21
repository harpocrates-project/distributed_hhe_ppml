#include <grpcpp/grpcpp.h>
#include "gen_code/hhe.grpc.pb.h"
#include <grpcpp/ext/proto_server_reflection_plugin.h>

using hheproto::MyService;
using hheproto::MyRequest;
using hheproto::MyResponse;

class MyServiceImpl final : public MyService::Service {
    grpc::Status GetResponse(grpc::ServerContext* context, const MyRequest* request, MyResponse* response) override {
        response->set_response("Hello, " + request->message());
        return grpc::Status::OK;
    }
};

void RunServer() {
    std::string server_address("0.0.0.0:50051");
    MyServiceImpl service;

    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);

    // Register reflection service
    grpc::reflection::InitProtoReflectionServerBuilderPlugin();
    
    std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
    std::cout << "Server listening on " << server_address << std::endl;
    server->Wait();
}

int main(int argc, char** argv) {
    RunServer();
    return 0;
}