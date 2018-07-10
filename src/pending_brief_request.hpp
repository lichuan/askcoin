#ifndef PENDING_BRIEF_REQUEST
#define PENDING_BRIEF_REQUEST

#include "pending_chain.hpp"

class Pending_Brief_Request
{
public:
    Pending_Brief_Request();
    void del_peer(std::shared_ptr<net::p2p::Peer> peer);
    
public:
    std::vector<std::shared_ptr<net::p2p::Peer>> m_peers;
    uint8 m_state;
    uint32 m_try_num;
    uint64 m_timer_id;
    uint32 m_last_idx;
};

#endif
