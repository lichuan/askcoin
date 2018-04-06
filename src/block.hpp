#ifndef BLOCK
#define BLOCK

#include "transaction.hpp"

class Block
{
public:
    Block(uint64 id, uint32 utc, uint32 version, uint32 zero_bits, std::string hash);
    bool is_genesis_block();
    uint32 version();
    uint32 utc();
    uint64 id();
    std::string hash();
    
private:
    uint64 m_id;
    uint32 m_utc;
    uint32 m_version;
    uint32 m_zero_bits;
    std::string m_hash;
};

#endif
