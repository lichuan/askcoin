#include <unistd.h>
#include "fly/base/logger.hpp"
#include "fly/net/server.hpp"
#include "net/p2p/node.hpp"

using namespace std::placeholders;

namespace net {
namespace p2p {

Node::Node()
{
}

Node::~Node()
{
}

bool Node::start(uint32 port)
{
    int32 cpu_num = sysconf(_SC_NPROCESSORS_ONLN);
    cpu_num = cpu_num < 4 ? 4 : cpu_num;
    m_poller.reset(new fly::net::Poller<Json>(cpu_num));
    std::unique_ptr<fly::net::Server<Json>> server(new fly::net::Server<Json>(fly::net::Addr("0.0.0.0", port),
                                                                              std::bind(&Node::allow, this, _1),
                                                                              std::bind(&Node::init, this, _1),
                                                                              std::bind(&Node::dispatch, this, _1),
                                                                              std::bind(&Node::close, this, _1),
                                                                              std::bind(&Node::be_closed, this, _1),
                                                                              m_poller));
    m_poller->start();

    if(server->start())
    {
        CONSOLE_LOG_INFO("start p2p node success");
        m_server = std::move(server);

        return true;
    }

    CONSOLE_LOG_FATAL("start p2p node failed!");

    return false;
}

void Node::stop()
{
    m_server->stop();
    m_poller->stop();
    CONSOLE_LOG_INFO("stop p2p node success");
}

void Node::wait()
{
    m_server->wait();
    m_poller->wait();
}

void Node::set_host(std::string host)
{
    m_host = host;
}

void Node::set_max_conn(uint32 num)
{
    m_max_conn = num;
}

bool Node::allow(std::shared_ptr<fly::net::Connection<Json>> connection)
{
    return true;
}

void Node::init(std::shared_ptr<fly::net::Connection<Json>> connection)
{
    std::lock_guard<std::mutex> guard(m_mutex);
    //m_connections[connection->id()] = connection;
    LOG_INFO("connection count: %u", m_peers.size());
}

// rapidjson::Document doc;
// doc.SetObject();
// rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
// doc.AddMember("msg_type", 9922, allocator); 
// doc.AddMember("msg_cmd", 2223333, allocator);
// connection->send(doc);

void Node::dispatch(std::unique_ptr<fly::net::Message<Json>> message)
{
    std::shared_ptr<fly::net::Connection<Json>> connection = message->get_connection();
    const fly::net::Addr &addr = connection->peer_addr();
    LOG_INFO("recv message from %s:%d raw_data: %s", addr.m_host.c_str(), addr.m_port, message->raw_data().c_str());
}
    
void Node::close(std::shared_ptr<fly::net::Connection<Json>> connection)
{
    LOG_INFO("close connection from %s:%d", connection->peer_addr().m_host.c_str(), connection->peer_addr().m_port);
    std::lock_guard<std::mutex> guard(m_mutex);
    //m_connections.erase(connection->id());
    LOG_INFO("connection count: %u", m_peers.size());
}
    
void Node::be_closed(std::shared_ptr<fly::net::Connection<Json>> connection)
{
    LOG_INFO("connection from %s:%d be closed", connection->peer_addr().m_host.c_str(), connection->peer_addr().m_port);
    std::lock_guard<std::mutex> guard(m_mutex);
    //m_connections.erase(connection->id());
    LOG_INFO("connection count: %u", m_peers.size());
}

bool Node::add_peer_score(const std::shared_ptr<Peer_Score> &peer_score)
{
    std::string key = peer_score->key();
    
    if(m_peer_score_map.find(key) != m_peer_score_map.end())
    {
        return false;
    }
    
    m_peer_scores.insert(peer_score);
    m_peer_score_map.insert(std::make_pair(key, peer_score));
    
    return true;
}

bool Node::del_peer_score(const std::shared_ptr<Peer_Score> &peer_score)
{
    std::string key = peer_score->key();
    
    if(m_peer_score_map.find(key) != m_peer_score_map.end())
    {
        return false;
    }
    
    m_peer_score_map.erase(key);
    auto iter_end = m_peer_scores.upper_bound(peer_score);
    
    for(auto iter = m_peer_scores.lower_bound(peer_score); iter != iter_end; ++iter)
    {
        if(*iter == peer_score)
        {
            m_peer_scores.erase(peer_score);

            return true;
        }
    }

    return false;
}

}
}
