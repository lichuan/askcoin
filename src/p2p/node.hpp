#ifndef P2P__NODE
#define P2P__NODE

#include <unordered_map>
#include "fly/net/server.hpp"
#include "fly/base/singleton.hpp"

using fly::net::Json;

namespace p2p {

class Node : public fly::base::Singleton<Node>
{
public:
    Node();
    ~Node();
    bool start(uint32 port);
    void stop();
    void wait();
    void set_max_active_conn(uint32 num);
    void set_max_passive_conn(uint32 num);
    bool allow(std::shared_ptr<fly::net::Connection<Json>> connection);
    void init(std::shared_ptr<fly::net::Connection<Json>> connection);
    void dispatch(std::unique_ptr<fly::net::Message<Json>> message);
    void close(std::shared_ptr<fly::net::Connection<Json>> connection);
    void be_closed(std::shared_ptr<fly::net::Connection<Json>> connection);
    void set_peer_file(std::string peer_file);
    void set_host(std::string host);

private:
    uint32 m_max_active_conn = 0;
    uint32 m_max_passive_conn = 0;
    std::unordered_map<uint64, std::shared_ptr<fly::net::Connection<Json>>> m_connections;
    std::mutex m_mutex;
    std::string m_host;
    std::string m_peer_file;
    std::unique_ptr<fly::net::Server<Json>> m_server;
    std::shared_ptr<fly::net::Poller<Json>> m_poller;
    std::shared_ptr<fly::net::Parser<Json>> m_parser;
};

}

#endif
