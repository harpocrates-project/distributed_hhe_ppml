mkdir ./src/gen_code
cmake -S . -B build -DCMAKE_PREFIX_PATH=libs/seal
cmake --build build
# ./build/PocketHHE
