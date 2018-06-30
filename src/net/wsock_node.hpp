#ifndef NET__WSOCK_NODE
#define NET__WSOCK_NODE

#include <unordered_map>
#include "fly/net/server.hpp"
#include "fly/base/singleton.hpp"

using fly::net::Wsock;

namespace net {

class Wsock_Node : public fly::base::Singleton<Wsock_Node>
{
public:
    Wsock_Node();
    ~Wsock_Node();

    bool start(uint16 port);
    void stop();
    void wait();
    void set_max_conn(uint32 num);
    bool allow(std::shared_ptr<fly::net::Connection<Wsock>> connection);
    void init(std::shared_ptr<fly::net::Connection<Wsock>> connection);
    void dispatch(std::unique_ptr<fly::net::Message<Wsock>> message);
    void close(std::shared_ptr<fly::net::Connection<Wsock>> connection);
    void be_closed(std::shared_ptr<fly::net::Connection<Wsock>> connection);

private:
    uint32 m_max_conn = 0;
    std::unordered_map<uint64, std::shared_ptr<fly::net::Connection<Wsock>>> m_connections;
    std::mutex m_mutex;
    std::unique_ptr<fly::net::Server<Wsock>> m_server;
};

}

#endif
