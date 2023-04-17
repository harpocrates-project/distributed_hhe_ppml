# Three Parties Privacy Preserving Machine Learning through Hybrid Homomorphic Encryption

This repository contains the implementation of a three parties Privacy Preserving Machine Learning (PPML) protocol based on Hybrid Homomorphic Encryption (HHE). The system provides a fully distributed version of the protocol already available at [HHE-PPML](https://github.com/iammrgenie/hhe_ppml)
and as such, it also depends on the [SEAL](https://github.com/microsoft/SEAL) (for HE) and [PASTA](https://github.com/IAIK/hybrid-HE-framework) (for HHE) libraries.

## Requirements
`cpp==9.4.0`   
`CMAKE>=3.13`  
`SEAL==4.0.0`  

The [Microsoft SEAL library](https://github.com/microsoft/SEAL) is already installed in `libs/seal`. Also, our code is based on the [PASTA framework for HHE](https://github.com/IAIK/hybrid-HE-framework). Moreover, the system currently uses [gRPC](https://grpc.io) and [Protobuf](https://protobuf.dev) to allow the communication between the parties. If these two dependencies are not already installed on the target system, they can be downloaded, compiled and added to the project directory via `cmake`. The above behaviour can be configured via changing the option `set(USE_SYSTEM_GRPC OFF)` in the `CMakeLists.txt` file.

## Repository Structure
```
├── configs              
│   ├── config.cpp  # holds the configurations (HE parameters, number of runs for experiments...)
├── pasta           # holds the definition of the PASTA components
├── proto           # holds the definition of the RPC services and protocol buffers
├── src             # holds the sources of the components needed to build the protocol
├── tests           # holds the unit tests
└── util            # holds the utility code used in PASTA and for data communication via sockets
 ```

## Simple HHE protocol description
The protocol consists of 3 parties: a client who holds the data, the analyst who holds the neural network weights and biases, and the cloud service provider (CSP) who holds the computing power.  
1. First, the analyst creates the necessary HE parameters and keys. 
2. Then, the analyst sends the public key to the client and the evaluation key to the CSP to compute on encrypted data.
3. Next, the analyst encrypts his weights and biases using HE and send them to the CSP. The encrypted weights and biases are denoted `c_w` and `c_b` respectively.
4. The client generates a symmetric key (`K`) and encrypts his plaintext data (`x`) using a symmetric key encryption algorithm. We denote the symmetrically encrypted data `c`. He also uses the HE public key to homomorphically encrypt his symmetric key, which is `c_K`.
5. The client sends both `c` and `c_K` to the CSP.
6. After receiving the HE evaluation key `evk` from the analyst, `c` and `c_K` from the client, the CSP performs the HHE decomposition algorithm to turn `c` into `c'`, where `c'` is the HE encrypted version of `x`. The CSP then can perform HE computations on `c'`, `c_w` and `c_b` and get the result `c_res`.
7. The CSP sends `c_res` to the analyst who can decrypt it using the HE private key to get the answers on data he did not get access to.

The above steps are implemented via invocation of the RPC methods and the exchange of the messages defined in the file `protos/hhe.proto`.

## Running
In the terminal, `cd` into the project's directory, then run
- `cmake -S . -B build -DCMAKE_PREFIX_PATH=libs/seal`  
- `cmake --build build`  
- Please, note that this process may initially take a long time due to the gRPC and Protobuf dependencies being downloaded and built. As soon as the project and the dependencies are built, the produced executables will be available in the `./build` directory. Please, also note that at the moment the workflow is implemented so that the components must be started according to the same order as they are listed below.

### CSP
The CSP component can be started via the command
```
./build/csp <address>:<port>
```
Where `address` and `port` are the local IP address and the port number on which the CSP will listen for incoming RPC requests. If no (or a wrong number of) arguments are provided, the CSP will listen on a default address and port number, i.e., `localhost:50052`.

### Analyst
The Analyst component can be started via the command
```
./build/analyst <localAddress>:<localPort> <cspAddress>:<cspPort>
```
Where `localAddress` and `localPort` are the IP address and port number on which the Analyst will listen for incoming RPC requests; `cspAddress` and `cspPort` are the parameters to be used in order to connect to the CSP. If no (or a wrong number of) arguments are provided, the Analyst by default will listen on `localhost:50051` and will assume the CSP can be reached for RPC invocations at `localhost:50052`.

### User
The User component can be started via the command
```
./build/user <analystAddress>:<analystPort> <cspAddress>:<cspPort>
```
Where `analystAddress` and `analystPort` are the IP address and port number of the Analyst; `cspAddress` and `cspPort` are the IP address and port number of the CSP. If no (or a wrong number of) arguments are provided, the User will assume the Analyst and the CSP are listening for RPC calls on `localhost:50051` and `localhost:50052` respectively.
