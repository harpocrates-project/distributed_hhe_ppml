cmake_minimum_required(VERSION 3.5.1)

project(Distributed_HHE)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 17)

#Set this to ON if GRPC and Protobuf are installed on the system
set(USE_SYSTEM_GRPC OFF)

find_package(SEAL 4.0.0 EXACT REQUIRED)

include(CheckCCompilerFlag)
function(check_c_compiler_flag_and_add flag result)
  check_c_compiler_flag("${flag}" ${result})
  if(${result})
    add_compile_options("${flag}")
  endif()
endfunction()

if(USE_SYSTEM_GRPC)
  # Find Protobuf installation
  # Looks for protobuf-config.cmake file installed by Protobuf's cmake installation.
  set(protobuf_MODULE_COMPATIBLE TRUE)
  find_package(Protobuf CONFIG REQUIRED)
  message(STATUS "Using protobuf ${Protobuf_VERSION}")

  set(_PROTOBUF_LIBPROTOBUF protobuf::libprotobuf)
  set(_REFLECTION gRPC::grpc++_reflection)
  if(CMAKE_CROSSCOMPILING)
    find_program(_PROTOBUF_PROTOC protoc)
  else()
    set(_PROTOBUF_PROTOC $<TARGET_FILE:protobuf::protoc>)
  endif()

  # Find gRPC installation
  # Looks for gRPCConfig.cmake file installed by gRPC's cmake installation.
  find_package(gRPC CONFIG REQUIRED)
  message(STATUS "Using gRPC ${gRPC_VERSION}")

  set(_GRPC_GRPCPP gRPC::grpc++)
  if(CMAKE_CROSSCOMPILING)
    find_program(_GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin)
  else()
    set(_GRPC_CPP_PLUGIN_EXECUTABLE $<TARGET_FILE:gRPC::grpc_cpp_plugin>)
  endif()
else()  
  include(FetchContent)
  FetchContent_Declare(
    gRPC
    GIT_REPOSITORY https://github.com/grpc/grpc
    GIT_TAG        v1.53.0
  )
  set(FETCHCONTENT_QUIET OFF)
  FetchContent_MakeAvailable(gRPC)

  set(_PROTOBUF_LIBPROTOBUF libprotobuf)
  set(_REFLECTION grpc++_reflection)
  set(_PROTOBUF_PROTOC $<TARGET_FILE:protoc>)
  set(_GRPC_GRPCPP grpc++)
  if(CMAKE_CROSSCOMPILING)
    find_program(_GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin)
  else()
    set(_GRPC_CPP_PLUGIN_EXECUTABLE $<TARGET_FILE:grpc_cpp_plugin>)
  endif()
endif()

# for AES code
if(MSVC)
  add_definitions("-DOC_ENABLE_SSE2")
  message("-- Enabling SSE2 for AES")
  add_definitions("-DOC_ENABLE_AESNI")
  message("-- Enabling AES_NI")
else()
  check_c_compiler_flag_and_add(-msse2 CC_SUPPORTS_SSE2)
  if(CC_SUPPORTS_SSE2)
    add_definitions("-DOC_ENABLE_SSE2")
    message("-- Enabling SSE2 for AES")
  endif()

  check_c_compiler_flag_and_add(-maes CC_SUPPORTS_AES)
  if(CC_SUPPORTS_AES)
    add_definitions("-DOC_ENABLE_AESNI")
    message("-- Enabling AES_NI")
  else()
    add_definitions("-DOC_ENABLE_PORTABLE_AES")
  endif()
endif()


include_directories(/usr/local/include)
include_directories(pasta)
include_directories(configs)
add_subdirectory(util)

# Proto file
get_filename_component(hhe_proto "./protos/hhe.proto" ABSOLUTE)
get_filename_component(hhe_proto_path "${hhe_proto}" PATH)

# Generated sources
set(hhe_proto_srcs "${CMAKE_SOURCE_DIR}/src/hhe.pb.cc")
set(hhe_proto_hdrs "${CMAKE_SOURCE_DIR}/src/hhe.pb.h")
set(hhe_grpc_srcs "${CMAKE_SOURCE_DIR}/src/hhe.grpc.pb.cc")
set(hhe_grpc_hdrs "${CMAKE_SOURCE_DIR}/src/hhe.grpc.pb.h")
add_custom_command(
      OUTPUT "${hhe_proto_srcs}" "${hhe_proto_hdrs}" "${hhe_grpc_srcs}" "${hhe_grpc_hdrs}"
      COMMAND ${_PROTOBUF_PROTOC}
      ARGS --grpc_out "${CMAKE_SOURCE_DIR}/src"
        --cpp_out "${CMAKE_SOURCE_DIR}/src"
        -I "${hhe_proto_path}"
        --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${hhe_proto}"
      DEPENDS "${hhe_proto}")

# Include generated *.pb.h files
include_directories("${CMAKE_SOURCE_DIR}/src")

add_executable(analyst src/AnalystRPC.cpp)
add_executable(user src/UserRPC.cpp)
add_executable(csp src/CSPRPC.cpp)


target_sources(analyst
        PRIVATE
            src/Analyst.cpp
            src/CSPServiceAnalystClient.cpp
            pasta/SEAL_Cipher.cpp
            pasta/pasta_3_seal.cpp
            pasta/pasta_3_plain.cpp
            pasta/utils.cpp
            configs/config.cpp)

target_sources(user
        PRIVATE
            src/User.cpp
            src/AnalystServiceUserClient.cpp
            src/CSPServiceUserClient.cpp
            pasta/SEAL_Cipher.cpp
            pasta/pasta_3_seal.cpp
            pasta/pasta_3_plain.cpp
            pasta/utils.cpp
            configs/config.cpp)

target_sources(csp
        PRIVATE
            src/CSP.cpp
            src/AnalystServiceCSPClient.cpp
            pasta/SEAL_Cipher.cpp
            pasta/pasta_3_seal.cpp
            pasta/pasta_3_plain.cpp
            pasta/utils.cpp
            configs/config.cpp)


# hhe_grpc_proto
add_library(hhe_grpc_proto
  ${hhe_grpc_srcs}
  ${hhe_grpc_hdrs}
  ${hhe_proto_srcs}
  ${hhe_proto_hdrs})
target_link_libraries(hhe_grpc_proto
  ${_REFLECTION}
  ${_GRPC_GRPCPP}
  ${_PROTOBUF_LIBPROTOBUF})

target_link_libraries(analyst SEAL::seal keccak aes 
	              hhe_grpc_proto ${_REFLECTION} ${_GRPC_GRPCPP} ${_PROTOBUF_LIBPROTOBUF})

target_link_libraries(user SEAL::seal keccak aes
                      hhe_grpc_proto ${_REFLECTION} ${_GRPC_GRPCPP} ${_PROTOBUF_LIBPROTOBUF})

target_link_libraries(csp SEAL::seal keccak aes
                      hhe_grpc_proto ${_REFLECTION} ${_GRPC_GRPCPP} ${_PROTOBUF_LIBPROTOBUF})
