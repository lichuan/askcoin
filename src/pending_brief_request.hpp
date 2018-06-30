#ifndef PENDING_BRIEF_REQUEST
#define PENDING_BRIEF_REQUEST

#include "pending_chain.hpp"

class Pending_Brief_Request
{
public:
    Pending_Brief_Request();
    void add_chain(std::shared_ptr<Pending_Chain> chain);

public:
    std::vector<std::shared_ptr<net::p2p::Peer>> m_peers;
    std::list<std::shared_ptr<Pending_Chain>> m_chains;
};

#endif
