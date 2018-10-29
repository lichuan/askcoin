#ifndef PENDING_BLOCK
#define PENDING_BLOCK

#include <list>
#include <memory>
#include "fly/base/common.hpp"
#include "accum_pow.hpp"
#include "rapidjson/document.h"

class Block;

class Pending_Block
{
public:
    Pending_Block(uint64 id, uint64 utc, uint32 version, uint32 zero_bits, std::string hash, std::string pre_hash, std::string data_hash);
    void add_difficulty_from(std::shared_ptr<Block> other);
    void add_difficulty_from(std::shared_ptr<Pending_Block> other);
    uint64 m_id;
    uint64 m_utc;
    uint32 m_version;
    uint32 m_zero_bits;
    std::string m_hash;
    std::string m_pre_hash;
    std::string m_data_hash;
    Accum_Pow m_accum_pow;
    std::shared_ptr<rapidjson::Document> m_doc;
};

#endif
