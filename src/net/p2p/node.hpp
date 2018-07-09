#ifndef NET__P2P__NODE
#define NET__P2P__NODE

#include <unordered_map>
#include <set>
#include <unordered_set>
#include <thread>
#include "fly/net/poller.hpp"
#include "fly/base/singleton.hpp"
#include "fly/base/block_queue.hpp"
#include "net/p2p/peer_score.hpp"
#include "net/p2p/peer.hpp"
#include "timer.hpp"

using fly::net::Json;
class Blockchain;

namespace net {
namespace p2p {

class Node : public fly::base::Singleton<Node>
{
    friend class ::Blockchain;
    
public:
    Node();
    ~Node();
    bool start(uint16 port);
    void stop();
    void wait();
    void set_max_conn(uint32 num);
    uint32 get_max_conn();
    bool allow(std::shared_ptr<fly::net::Connection<Json>> connection);
    void init(std::shared_ptr<fly::net::Connection<Json>> connection);
    void init_verify(std::shared_ptr<fly::net::Connection<Json>> connection, uint64 id);
    void dispatch(std::unique_ptr<fly::net::Message<Json>> message);
    void close(std::shared_ptr<fly::net::Connection<Json>> connection);
    void be_closed(std::shared_ptr<fly::net::Connection<Json>> connection);
    void set_host(std::string host);
    bool add_peer_score(const std::shared_ptr<Peer_Score> &peer_score);
    bool del_peer_score(const std::shared_ptr<Peer_Score> &peer_score);
    bool insert_peer_score(const std::shared_ptr<Peer_Score> &peer_score);
    bool erase_peer_score(const std::shared_ptr<Peer_Score> &peer_score);
    void connect_proc();
    void timer_proc();

private:
    uint32 m_max_conn = 0;
    std::atomic<bool> m_stop{false};
    std::unordered_map<uint64, std::shared_ptr<Peer>> m_peers;
    std::unordered_map<uint64, std::shared_ptr<Peer>> m_unreg_peers;
    std::unordered_map<std::string, std::shared_ptr<Peer_Score>> m_peer_score_map;
    std::unordered_set<std::string> m_banned_peers;
    std::multiset<std::shared_ptr<Peer_Score>, Peer_Score::Score_Comp> m_peer_scores;
    std::mutex m_score_mutex;
    std::mutex m_peer_mutex;
    std::string m_host;
    uint16 m_port;
    std::unique_ptr<fly::net::Server<Json>> m_server;
    std::shared_ptr<fly::net::Poller<Json>> m_poller;
    std::thread m_connect_thread;
    std::thread m_timer_thread;
    Timer_Controller m_timer_ctl;
};

}
}

#endif
