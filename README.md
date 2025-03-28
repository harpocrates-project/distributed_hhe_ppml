# Three Parties Privacy Preserving Machine Learning through Hybrid Homomorphic Encryption

An Integer-only, Lightweight Privacy-preserving Machine Learning Framework with Hybrid Homomorphic Encryption (HHE). The system provides a fully distributed version of the protocol already available at [HHE-PPML](https://github.com/iammrgenie/hhe_ppml)
and as such, it also depends on the [SEAL](https://github.com/microsoft/SEAL), [PASTA](https://github.com/IAIK/hybrid-HE-framework) and [PocketNN](https://github.com/khoaguin/PocketNN).

## Datasets

The image datasets used in this project are copied from their original website and are stored in `data/`

- MNIST dataset: MNIST dataset is from [the MNIST website](http://yann.lecun.com/exdb/mnist/)
- Fashion-MNIST dataset: Fashion-MNIST dataset is from [its github repository](https://github.com/zalandoresearch/fashion-mnist).

We use the processed ECG dataset from [this work](https://github.com/SharifAbuadbba/split-learning-1D) which is originally the [MIT-BIH 1.0 from Physionet](https://www.physionet.org/content/mitdb/1.0.0/).

## Repo structure

```
├── configs         # hold the configuration parameters needed to run experiments
├── data            # hold the datasets
├── images          # hold the images in `README.md`
├── libs            # hold the libraries needed
├── notebooks       # hold the notebooks to train float neural nets on plaintext 
├── src             # hold the source code
├── proto           # hold the definition of the RPC services and protocol buffers
├── tests           # hold some unit tests
└── weights         # hold the trained weights and biases
```

## Requirements

`cpp==11.3.0`  
`CMAKE>=3.25.1`  
`SEAL==4.0.0`

The PASTA library for HHE is built upon Microsoft's SEAL library. In this repo, SEAL is already installed in `libs/seal`. If you want to install it somewhere else, please refer to the [SEAL's repo](https://github.com/microsoft/SEAL).

## How to run

Before compiling the application, you can take a look at `src/config.cpp` and change the configurations to your own settings. Notes:

- The `debugging` variable should be set to `false` if you are not debugging the application and to `true` if you want to debug (I used VSCode to debug so it might cause problems if you are not using VSCode).
- When `dry_run` is `true`, we only run a few data examples set by `dry_run_num_samples`. Otherwise it runs the whole dataset.
- `save_weight_path` and `save_bias_path` defines the paths that the trained weights and bias will be saved. It also defines the paths that the trained weights and bias will be loaded from in the inference protocols.

To compile and run this project, see the followings:
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
./build/user <analystAddress>:<analystPort> <cspAddress>:<cspPort> <dataSet>
```
Where `analystAddress` and `analystPort` are the IP address and port number of the Analyst; `cspAddress` and `cspPort` are the IP address and port number of the CSP. If no (or a wrong number of) arguments are provided, the User will assume the Analyst and the CSP are listening for RPC calls on `localhost:50051` and `localhost:50052` respectively. If no `dataSet` is specified, the components will use the default one located in `data/Harpocrates_recordingwise_SIESTA_4percent/c000101_data.txt`.

## Integration with external components
No specific interactions with external components is expected for the User and Analyst; they have been devised to be used via a command line interface. On the other hand, once data are received from the User by the CSP, they are automatically encrypted (HHE decomposition) and saved in a file, whose name includes the UUID of the designated Analyst. External components can later then trigger a model evaluation on these (or externally provided) data using one of the two gRPC endpoints described below.

These RPC definitions are part of a service that allows other components to request model evaluation using either direct ciphertext bytes or data from a file previously generated and saved by the CSP component. The use of Protocol Buffers ensures that these RPCs can be used across different programming languages and platforms, making the service highly interoperable. The CiphertextBytes message provides a way to pass encrypted data along with an analyst identifier (the UUID), while the DataFile message allows for specifying a file containing the necessary data for evaluation and reusing encrypted data already existing on the CSP.

### Model Evaluation with Encrypted Data

**`rpc evaluateModel (CiphertextBytes) returns (Empty) { }`**:
- Defines an RPC named `evaluateModel`. It takes a single parameter of type `CiphertextBytes` and returns a response of type `Empty`.
- The `CiphertextBytes` message type is defined as follows:

  ```proto3
  message CiphertextBytes {
      repeated bytes HHEDecomp = 1;
      string analystID = 2;
  }
  ```

- The `CiphertextBytes` message contains two fields:
     - `HHEDecomp`: A repeated field of bytes, which likely represents a collection of encrypted data segments.
     - `analystID`: A string that identifies the UUID of the analyst associated with the encrypted data.
- The `Empty` return type is used to acknowledge that the operation has been completed.


### Model Evaluation with File Name

**`rpc evaluateModelFromFile (DataFile) returns (Empty) { }`**:
- Defines an RPC named `evaluateModelFromFile`. It takes a single parameter of type `DataFile` and also returns a response of type `Empty`.
- The `DataFile` message type is defined as follows:

  ```proto3
  message DataFile {
      string filename = 1;
  }
  ```

- The `DataFile` message contains a single field:
     - `filename`: A string that specifies the name of the file (existing on the CSP component file system) containing the data to be used for model evaluation.
- Similar to the previous RPC, the `Empty` return type is utilised to provide an acknowledgment of completion.