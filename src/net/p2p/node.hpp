#ifndef NET__P2P__NODE
#define NET__P2P__NODE

#include <unordered_map>
#include <set>
#include "fly/net/poller.hpp"
#include "fly/base/singleton.hpp"
#include "net/p2p/peer_score.hpp"
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
    void set_max_conn(uint32 num);
    bool allow(std::shared_ptr<fly::net::Connection<Json>> connection);
    void init(std::shared_ptr<fly::net::Connection<Json>> connection);
    void dispatch(std::unique_ptr<fly::net::Message<Json>> message);
    void close(std::shared_ptr<fly::net::Connection<Json>> connection);
    void be_closed(std::shared_ptr<fly::net::Connection<Json>> connection);
    void set_host(std::string host);
    bool add_peer_score(const std::shared_ptr<Peer_Score> &peer_score);
    bool del_peer_score(const std::shared_ptr<Peer_Score> &peer_score);

private:
    uint32 m_max_conn = 0;
    std::unordered_map<uint64, std::shared_ptr<Peer>> m_peers;
    std::unordered_map<std::string, std::shared_ptr<Peer_Score>> m_peer_score_map;
    std::multiset<std::shared_ptr<Peer_Score>, Peer_Score::Score_Comp> m_peer_scores;
    std::mutex m_mutex;
    std::string m_host;
    std::unique_ptr<fly::net::Server<Json>> m_server;
    std::shared_ptr<fly::net::Poller<Json>> m_poller;
};

}
}

#endif
