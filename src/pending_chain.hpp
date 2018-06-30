#ifndef PENDING_CHAIN
#define PENDING_CHAIN

#include <memory>
#include "pending_block.hpp"
#include "accum_pow.hpp"

namespace net {
namespace p2p {

class Peer;

}
}

class Pending_Chain
{
public:
    Pending_Chain(std::shared_ptr<net::p2p::Peer> peer, std::shared_ptr<Pending_Block> block, Accum_Pow declared_pow);
    
public:
    Accum_Pow m_declared_pow;
    std::list<std::shared_ptr<Pending_Block>> m_blocks;
    std::list<std::shared_ptr<net::p2p::Peer>> m_same_chain_peers;
    std::list<std::shared_ptr<net::p2p::Peer>> m_peers;
    std::shared_ptr<Pending_Block> m_block;
    Accum_Pow m_remain_pow;
};

#endif
