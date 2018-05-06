#ifndef BLOCK
#define BLOCK

#include <memory>
#include "accum_pow.hpp"

class Block
{
public:
    Block(uint64 id, uint32 utc, uint32 version, uint32 zero_bits, std::string hash);
    bool is_genesis();
    uint32 version();
    uint32 utc();
    uint64 id();
    std::string hash();
    uint32 zero_bits();
    void set_parent(std::shared_ptr<Block> parent);
    void add_child(std::shared_ptr<Block> child);

private:
    uint64 m_id;
    uint32 m_utc;
    uint32 m_version;
    uint32 m_zero_bits;
    std::string m_hash;
    std::shared_ptr<Block> m_parent;
    std::vector<std::shared_ptr<Block>> m_children;
    Accum_Pow m_accum_pow;
};

class Pending_Block : public Block
{
public:
    Pending_Block(uint64 id, uint32 utc, uint32 version, uint32 zero_bits, std::string hash);
    ~Pending_Block();
    void exec();
    void exec_reverse();
};

#endif
