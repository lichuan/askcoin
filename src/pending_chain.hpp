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
    struct Brief_Req_State
    {
        std::shared_ptr<Pending_Block> m_cur_block;
        bool m_requested;

        Brief_Req_State()
        {
            m_requested = false;
        }
    };
    
    Pending_Chain();
    Pending_Chain(std::shared_ptr<net::p2p::Peer> peer, std::shared_ptr<Pending_Block> block, Accum_Pow declared_pow);
    
public:
    Accum_Pow m_declared_pow;
    Brief_Req_State m_brief_req_state;
    std::deque<std::string> m_block_hashes;
    std::shared_ptr<net::p2p::Peer> m_peer;
    Accum_Pow m_remain_pow;
};

#endif
