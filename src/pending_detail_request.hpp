#ifndef PENDING_DETAIL_REQUEST
#define PENDING_DETAIL_REQUEST

#include "pending_chain.hpp"

class Pending_Detail_Request
{
public:
    Pending_Detail_Request();

public:
    std::list<std::shared_ptr<Pending_Chain>> m_attached_chains;
    std::shared_ptr<Pending_Chain> m_owner_chain;
    uint32 m_try_num;
    uint64 m_timer_id;
};

#endif
