#include "leveldb/db.h"
#include "leveldb/comparator.h"
#include "fly/base/logger.hpp"
#include "branchchain.hpp"
#include "key.h"
#include "utilstrencodings.h"
#include "cryptopp/sha.h"
#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

Branchchain::Branchchain()
{
}

Branchchain::~Branchchain()
{
}
