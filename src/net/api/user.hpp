#ifndef NET__API__USER
#define NET__API__USER

#include "fly/net/connection.hpp"

using fly::net::Wsock;

namespace net {
namespace api {

class User
{
public:
    User();
    ~User();
    std::shared_ptr<fly::net::Connection<Wsock>> m_connection;
    uint8 m_state;
    std::string m_pubkey;
    uint64 m_timer_id;
};

}
}

#endif
