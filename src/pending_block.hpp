#ifndef PENDING_BLOCK
#define PENDING_BLOCK

#include <list>
#include "fly/base/common.hpp"

class Pending_Block
{
public:
    Pending_Block(uint64 id, uint64 utc, uint32 version, uint32 zero_bits, std::string hash, std::string pre_hash);
    uint64 m_id;
    uint64 m_utc;
    uint32 m_version;
    uint32 m_zero_bits;
    std::string m_hash;
    std::string m_pre_hash;
    std::string m_miner_pubkey;
    std::list<std::string> m_tx_ids;
};

#endif
