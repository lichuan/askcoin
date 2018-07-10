#include "pending_brief_request.hpp"

Pending_Brief_Request::Pending_Brief_Request()
{
    m_state = 0;
    m_try_num = 1;
    m_timer_id = 0;
    m_last_idx = 0;
}

void Pending_Brief_Request::del_peer(std::shared_ptr<net::p2p::Peer> peer)
{
    for(auto iter = m_peers.begin(); iter != m_peers.end(); ++iter)
    {
        if(*iter == peer)
        {
            m_peers.erase(iter);

            break;
        }
    }
}
