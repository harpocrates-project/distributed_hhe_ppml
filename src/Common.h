#pragma once

#include <iostream>
#include <vector>
#include <chrono>
#include <cassert>
#include <string>
#include <typeinfo>

#include <pocketnn/pktnn.h>
#include <seal/seal.h>

#include "../configs/config.h"
#include "./util/sealhelper.h"
#include "./util/pastahelper.h"
#include "./util/utils.h"
#include "./util/matrix.h"
#include "./util/checks.h"
#include "./pasta/pasta_3_plain.h"
#include "./pasta/pasta_3_seal.h"
#include "./pasta/SEAL_Cipher.h"

using namespace std;
using namespace seal;
using namespace sealhelper;
using namespace pastahelper;

