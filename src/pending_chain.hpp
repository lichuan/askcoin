#ifndef PENDING_CHAIN
#define PENDING_CHAIN

#include <memory>
#include <deque>
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
    Pending_Chain();
    Pending_Chain(std::shared_ptr<net::p2p::Peer> peer, std::shared_ptr<Pending_Block> block, Accum_Pow declared_pow);
    
public:
    Accum_Pow m_declared_pow;
    std::deque<std::shared_ptr<Pending_Block>> m_req_blocks;
    std::shared_ptr<net::p2p::Peer> m_peer;
    Accum_Pow m_remain_pow;
    uint64 m_start;
    bool m_detail_attached;
    bool m_brief_attached;
};

#endif
