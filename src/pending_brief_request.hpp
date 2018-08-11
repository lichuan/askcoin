#ifndef PENDING_BRIEF_REQUEST
#define PENDING_BRIEF_REQUEST

#include "pending_chain.hpp"

class Pending_Brief_Request
{
public:
    Pending_Brief_Request();
    std::vector<std::shared_ptr<Pending_Chain>> m_attached_chains;
    
public:
    std::string m_hash;
    uint32 m_try_num;
    uint64 m_timer_id;
};

#endif
