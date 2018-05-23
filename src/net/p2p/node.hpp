#ifndef NET__P2P__NODE
#define NET__P2P__NODE

#include <unordered_map>
#include <set>
#include "fly/net/server.hpp"
#include "fly/base/singleton.hpp"
#include "net/p2p/peer.hpp"

using fly::net::Json;

namespace net {
namespace p2p {

class Node : public fly::base::Singleton<Node>
{
public:
    Node();
    ~Node();
    bool start(uint32 port);
    void stop();
    void wait();
    void set_max_passive_conn(uint32 num);
    bool allow(std::shared_ptr<fly::net::Connection<Json>> connection);
    void init(std::shared_ptr<fly::net::Connection<Json>> connection);
    void dispatch(std::unique_ptr<fly::net::Message<Json>> message);
    void close(std::shared_ptr<fly::net::Connection<Json>> connection);
    void be_closed(std::shared_ptr<fly::net::Connection<Json>> connection);
    void set_host(std::string host);
    void add_init_peer(const fly::net::Addr &addr);
    bool add_peer(const Peer &peer);

private:
    uint32 m_max_passive_conn = 0;
    std::unordered_map<uint64, std::shared_ptr<fly::net::Connection<Json>>> m_connections;
    std::multiset<Peer, Peer::Score_Comp> m_peers;
    std::mutex m_mutex;
    std::string m_host;
    std::unique_ptr<fly::net::Server<Json>> m_server;
    std::shared_ptr<fly::net::Poller<Json>> m_poller;
    std::shared_ptr<fly::net::Parser<Json>> m_parser;
    std::vector<fly::net::Addr> m_init_peer;
};

}
}

#endif
