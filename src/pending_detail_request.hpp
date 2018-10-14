#ifndef PENDING_DETAIL_REQUEST
#define PENDING_DETAIL_REQUEST

#include <set>
#include "pending_chain.hpp"

class Pending_Detail_Request
{
public:
    struct Chain_Comp
    {
        bool operator()(const std::shared_ptr<Pending_Chain> &a, const std::shared_ptr<Pending_Chain> &b)
        {
            return a->m_peer->key() < b->m_peer->key();
        }
    };

    Pending_Detail_Request();
    std::list<std::shared_ptr<Pending_Chain>> m_attached_chains;
    std::set<std::shared_ptr<Pending_Chain>, Chain_Comp> m_chains;
    std::shared_ptr<Pending_Block> m_pb;
    uint32 m_try_num;
    uint64 m_timer_id;
    uint32 m_send_num;
};

#endif
