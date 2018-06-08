#include <unistd.h>
#include <chrono>
#include "fly/base/logger.hpp"
#include "fly/net/server.hpp"
#include "fly/net/client.hpp"
#include "net/p2p/node.hpp"
#include "message.hpp"
#include "version.hpp"
#include "blockchain.hpp"

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
    m_port = port;
    
    if(server->start())
    {
        CONSOLE_LOG_INFO("start p2p node success");
        m_server = std::move(server);
        std::thread tmp_thread(std::bind(&Node::connect_peer, this));
        m_thread = std::move(tmp_thread);
        
        return true;
    }
    
    CONSOLE_LOG_FATAL("start p2p node failed!");

    return false;
}

void Node::stop()
{
    m_stop.store(true, std::memory_order_relaxed);
    m_server->stop();
    m_poller->stop();
    CONSOLE_LOG_INFO("stop p2p node success");
}

void Node::connect_peer()
{
    while(!m_stop.load(std::memory_order_relaxed))
    {
        m_timer_ctl.run();
        uint32 peer_num = 0;
        {
            std::lock_guard<std::mutex> guard(m_peer_mutex);
            peer_num = m_peers.size() + m_unreg_peers.size();
        }
        
        if(peer_num >= m_max_conn)
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));

            continue;
        }
        
        std::unique_lock<std::mutex> lock(m_score_mutex);
        
        for(auto iter = m_peer_scores.begin(); iter != m_peer_scores.end(); ++iter)
        {
            std::shared_ptr<Peer_Score> peer_score = *iter;
            uint32 expect = 0;

            if(peer_score->m_state.compare_exchange_strong(expect, 1))
            {
                lock.unlock();
                const fly::net::Addr &addr = peer_score->addr();
                std::unique_ptr<fly::net::Client<Json>> client(new fly::net::Client<Json>(addr,
                                                                                          std::bind(&Node::init, this, _1),
                                                                                          std::bind(&Node::dispatch, this, _1),
                                                                                          std::bind(&Node::close, this, _1),
                                                                                          std::bind(&Node::be_closed, this, _1),
                                                                                          m_poller));
                if(client->connect(1000))
                {
                    LOG_INFO("connect to peer (%s:%u) success", addr.m_host.c_str(), addr.m_port);
                }
                else
                {
                    LOG_ERROR("connect to peer (%s:%u) failed", addr.m_host.c_str(), addr.m_port);
                    peer_score->m_state.store(0, std::memory_order_relaxed);
                    lock.lock();
                    peer_score->sub_score(10);
                }
                
                break;
            }
        }
    }
}

void Node::wait()
{
    m_thread.join();
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
    uint32 peer_num = 0;
    {
        std::lock_guard<std::mutex> guard(m_peer_mutex);
        peer_num = m_peers.size() + m_unreg_peers.size();
    }
    
    if(peer_num >= m_max_conn)
    {
        return false;
    }
    
    return true;
}

void Node::init_verify(std::shared_ptr<fly::net::Connection<Json>> connection, uint64 id)
{
    uint64 conn_id = connection->id();
    std::shared_ptr<Peer> peer = std::make_shared<Peer>();
    peer->m_timer_id = m_timer_ctl.add_timer([=]() {
            connection->close();
        }, 10, true);
    peer->m_connection = connection;
    std::unique_lock<std::mutex> lock(m_peer_mutex);
    m_unreg_peers.insert(std::make_pair(conn_id, peer));
    auto iter_unreg = m_unreg_peers.find(id);
    
    if(iter_unreg == m_unreg_peers.end())
    {
        LOG_ERROR("init_verify unreg peer doesn't exist");
        connection->close();
        
        return;
    }

    std::shared_ptr<Peer> peer_unreg = iter_unreg->second;
    lock.unlock();
    rapidjson::Document doc;
    doc.SetObject();
    rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
    doc.AddMember("msg_type", MSG_REG, allocator);
    doc.AddMember("msg_cmd", REG_VERIFY_REQ, allocator);
    doc.AddMember("id", peer_unreg->m_reg_conn_id, allocator);
    doc.AddMember("key", peer_unreg->m_remote_key, allocator);
    connection->send(doc);
    peer_unreg->m_state = 4;
}

void Node::init(std::shared_ptr<fly::net::Connection<Json>> connection)
{
    uint64 conn_id = connection->id();
    std::shared_ptr<Peer> peer = std::make_shared<Peer>();
    peer->m_timer_id = m_timer_ctl.add_timer([=]() {
            connection->close();
        }, 10, true);
    peer->m_connection = connection;
    {
        std::lock_guard<std::mutex> guard(m_peer_mutex);
        m_unreg_peers.insert(std::make_pair(conn_id, peer));
    }
    
    if(!connection->is_passive())
    {
        peer->m_addr = fly::net::Addr(m_host, m_port);
        peer->m_state = 1;
        peer->m_local_key = fly::base::random_32();
        rapidjson::Document doc;
        doc.SetObject();
        rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
        doc.AddMember("msg_type", MSG_REG, allocator);
        doc.AddMember("msg_cmd", REG_REQ, allocator);
        doc.AddMember("host", rapidjson::StringRef(m_host.c_str()), allocator);
        doc.AddMember("port", m_port, allocator);
        doc.AddMember("id", conn_id, allocator);
        doc.AddMember("key", peer->m_local_key, allocator);
        doc.AddMember("version", ASKCOIN_VERSION, allocator);
        connection->send(doc);
    }
}

void Node::dispatch(std::unique_ptr<fly::net::Message<Json>> message)
{
    std::shared_ptr<fly::net::Connection<Json>> connection = message->get_connection();
    uint64 conn_id = connection->id();
    std::unique_lock<std::mutex> lock(m_peer_mutex);
    auto iter_reg = m_peers.find(conn_id);
    
    if(iter_reg != m_peers.end())
    {
        Blockchain::instance()->dispatch_peer_message(std::move(message));

        return;
    }
    
    auto iter_unreg = m_unreg_peers.find(conn_id);
    
    if(iter_unreg == m_unreg_peers.end())
    {
        LOG_ERROR("unreg peer doesn't exist");
        connection->close();
        
        return;
    }
    
    std::shared_ptr<Peer> peer = iter_unreg->second;
    lock.unlock();
    uint32 type = message->type();
    
    if(type != MSG_REG)
    {
        LOG_ERROR("unreg peer recv message type: %u not MSG_REG", type);
        connection->close();
        
        return;
    }

    rapidjson::Document& doc = message->doc();
    uint32 cmd = message->cmd();
    
    if(!connection->is_passive())
    {
        if(cmd == REG_RSP)
        {
            if(peer->m_state != 1)
            {
                LOG_ERROR("unreg peer recv message REG_RSP, but m_state is not 1");
                connection->close();
                
                return;
            }

            if(!doc.HasMember("version"))
            {
                connection->close();
                
                return;
            }
            
            const rapidjson::Value &version = doc["version"];

            if(!version.IsUint())
            {
                connection->close();
                
                return;
            }

            if(!doc.HasMember("id"))
            {
                connection->close();

                return;
            }
            
            const rapidjson::Value &id = doc["id"];

            if(!id.IsUint64())
            {
                connection->close();
                
                return;
            }

            if(!doc.HasMember("key"))
            {
                connection->close();

                return;
            }
            
            const rapidjson::Value &key = doc["key"];

            if(!key.IsUint())
            {
                connection->close();
                
                return;
            }
            
            uint32 version_u32 = version.GetUint();
            uint64 id_u64 = id.GetUint64();
            uint32 key_u32 = key.GetUint();
            LOG_INFO("unreg peer (m_state:1) recv message cmd REG_RSP, version:%u, id:%lu, key:%u", version_u32, id_u64, key_u32);

            if(!version_compatible(version_u32, ASKCOIN_VERSION))
            {
                LOG_ERROR("unreg peer (m_state:1) !version_compatible(%u,%u), addr: %s", version_u32, ASKCOIN_VERSION, peer->key().c_str());
                connection->close();

                return;
            }

            peer->m_remote_key = key_u32;
            peer->m_reg_conn_id = id_u64;
            peer->m_state = 3;
        }
        else if(cmd == REG_VERIFY_REQ)
        {
            if(peer->m_state != 0)
            {
                LOG_ERROR("verify unreg peer recv message REG_VERIFY_REQ, but m_state is not 0");
                connection->close();

                return;
            }

            if(!doc.HasMember("id"))
            {
                connection->close();

                return;
            }
            
            const rapidjson::Value &id = doc["id"];

            if(!id.IsUint64())
            {
                connection->close();
                
                return;
            }

            if(!doc.HasMember("key"))
            {
                connection->close();

                return;
            }
            
            const rapidjson::Value &key = doc["key"];

            if(!key.IsUint())
            {
                connection->close();
                
                return;
            }

            uint64 id_u64 = id.GetUint64();
            uint32 key_u32 = key.GetUint();
            LOG_INFO("verify unreg peer (m_state:0) recv message cmd REG_VERIFY_REQ, id:%lu, key:%u", id_u64, key_u32);
            std::unique_lock<std::mutex> lock(m_peer_mutex);
            auto iter_unreg = m_unreg_peers.find(id_u64);

            if(iter_unreg == m_unreg_peers.end())
            {
                LOG_ERROR("after recv message cmd REG_VERIFY_REQ, unreg peer doesn't exist");
                connection->close();
        
                return;
            }

            std::shared_ptr<Peer> peer_unreg = iter_unreg->second;
            lock.unlock();
        
            if(peer_unreg->m_state != 3)
            {
                LOG_ERROR("after recv message cmd REG_VERIFY_REQ, unreg peer m_state != 3");
                connection->close();
            
                return;
            }

            if(key_u32 != peer_unreg->m_local_key)
            {
                LOG_ERROR("after recv message cmd REG_VERIFY_REQ, unreg peer m_local_key != key_u32");
                connection->close();

                return;
            }

            m_timer_ctl.del_timer(peer_unreg->m_timer_id);
            rapidjson::Document doc;
            doc.SetObject();
            rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
            doc.AddMember("msg_type", MSG_REG, allocator);
            doc.AddMember("msg_cmd", REG_VERIFY_RSP, allocator);
            doc.AddMember("key", peer_unreg->m_remote_key, allocator);
            doc.AddMember("id", peer_unreg->m_reg_conn_id, allocator);
            connection->send(doc);
            lock.lock();
            m_unreg_peers.erase(id_u64);
            m_peers.insert(std::make_pair(id_u64, peer_unreg));
            connection->close();
        }
        else
        {
            connection->close();
        }
        
        return;
    }
    
    if(cmd == REG_REQ)
    {
        if(peer->m_state != 0)
        {
            LOG_ERROR("unreg peer recv message REG_REQ, but m_state is not 0");
            connection->close();

            return;
        }
        
        if(!doc.HasMember("version"))
        {
            connection->close();
                
            return;
        }
            
        const rapidjson::Value &version = doc["version"];

        if(!version.IsUint())
        {
            connection->close();
                
            return;
        }

        if(!doc.HasMember("id"))
        {
            connection->close();

            return;
        }
            
        const rapidjson::Value &id = doc["id"];

        if(!id.IsUint64())
        {
            connection->close();
                
            return;
        }

        if(!doc.HasMember("key"))
        {
            connection->close();

            return;
        }
            
        const rapidjson::Value &key = doc["key"];

        if(!key.IsUint())
        {
            connection->close();
                
            return;
        }

        if(!doc.HasMember("host"))
        {
            connection->close();

            return;
        }
            
        const rapidjson::Value &host = doc["host"];

        if(!host.IsString())
        {
            connection->close();
                
            return;
        }

        if(!doc.HasMember("port"))
        {
            connection->close();

            return;
        }
            
        const rapidjson::Value &port = doc["port"];

        if(!port.IsUint())
        {
            connection->close();
            
            return;
        }
        
        uint32 version_u32 = version.GetUint();
        uint64 id_u64 = id.GetUint64();
        std::string host_str = host.GetString();
        uint32 port_u32 = port.GetUint();
        uint32 key_u32 = key.GetUint();
        LOG_INFO("unreg peer (m_state:0) recv message cmd REG_REQ, version:%u, id:%lu, key:%u, host:%s, port:%u", version_u32, id_u64, key_u32, host_str.c_str(), port_u32);
        if(!version_compatible(version_u32, ASKCOIN_VERSION))
        {
            LOG_ERROR("unreg peer (m_state:0) !version_compatible(%u,%u), addr: %s:%u", version_u32, ASKCOIN_VERSION, host_str.c_str(), port_u32);
            connection->close();
            
            return;
        }
        
        peer->m_local_key = fly::base::random_32();
        peer->m_remote_key = key_u32;
        peer->m_reg_conn_id = id_u64;
        peer->m_addr = fly::net::Addr(host_str, port_u32);
        std::shared_ptr<Peer_Score> peer_score = std::make_shared<Peer_Score>(peer->m_addr);
        std::unique_lock<std::mutex> lock(m_score_mutex);
        auto iter = m_peer_score_map.find(peer_score->key());
        
        if(iter != m_peer_score_map.end())
        {
            peer_score = iter->second;
        }
        else
        {
            add_peer_score(peer_score);
        }
        
        lock.unlock();
        uint32 expect = 0;
        
        if(peer_score->m_state.compare_exchange_strong(expect, 1))
        {
            peer->m_state = 2;
            rapidjson::Document doc;
            doc.SetObject();
            rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
            doc.AddMember("msg_type", MSG_REG, allocator);
            doc.AddMember("msg_cmd", REG_RSP, allocator);
            doc.AddMember("id", conn_id, allocator);
            doc.AddMember("key", peer->m_local_key, allocator);
            doc.AddMember("version", ASKCOIN_VERSION, allocator);
            connection->send(doc);
            
            std::thread tmp_thread([=]() {
                    std::unique_ptr<fly::net::Client<Json>> client(new fly::net::Client<Json>(peer->m_addr,
                                                                                              std::bind(&Node::init_verify, this, _1, conn_id),
                                                                                              std::bind(&Node::dispatch, this, _1),
                                                                                              std::bind(&Node::close, this, _1),
                                                                                              std::bind(&Node::be_closed, this, _1),
                                                                                              m_poller));
                    if(client->connect(1000))
                    {
                        LOG_INFO("unreg peer (m_state:2) connect to peer (%s:%u) success", peer->m_addr.m_host.c_str(), peer->m_addr.m_port);
                    }
                    else
                    {
                        LOG_ERROR("unreg peer (m_state:2) connect to peer (%s:%u) failed", peer->m_addr.m_host.c_str(), peer->m_addr.m_port);
                        connection->close();
                        peer_score->m_state.store(0, std::memory_order_relaxed);
                        std::lock_guard<std::mutex> guard(m_score_mutex);
                        peer_score->sub_score(100);
                    }
                });
            tmp_thread.detach();
        }
        else
        {
            connection->close();
        }
    }
    else if(cmd == REG_VERIFY_RSP)
    {
        if(peer->m_state != 0)
        {
            LOG_ERROR("verify unreg peer recv message REG_VERIFY_RSP, but m_state is not 0");
            connection->close();
                
            return;
        }
            
        if(!doc.HasMember("id"))
        {
            connection->close();

            return;
        }
            
        const rapidjson::Value &id = doc["id"];

        if(!id.IsUint64())
        {
            connection->close();
                
            return;
        }

        if(!doc.HasMember("key"))
        {
            connection->close();

            return;
        }
            
        const rapidjson::Value &key = doc["key"];

        if(!key.IsUint())
        {
            connection->close();
                
            return;
        }

        uint64 id_u64 = id.GetUint64();
        uint32 key_u32 = key.GetUint();
        LOG_INFO("verify unreg peer (m_state:0) recv message cmd REG_VERIFY_RSP, id:%lu, key:%u", id_u64, key_u32);
        std::unique_lock<std::mutex> lock(m_peer_mutex);
        auto iter_unreg = m_unreg_peers.find(id_u64);

        if(iter_unreg == m_unreg_peers.end())
        {
            LOG_ERROR("after recv message cmd REG_VERIFY_RSP, unreg peer doesn't exist");
            connection->close();
        
            return;
        }
            
        std::shared_ptr<Peer> peer_unreg = iter_unreg->second;
        lock.unlock();
        
        if(peer_unreg->m_state != 4)
        {
            LOG_ERROR("after recv message cmd REG_VERIFY_RSP, unreg peer m_state != 4");
            connection->close();
            
            return;
        }

        if(key_u32 != peer_unreg->m_local_key)
        {
            LOG_ERROR("after recv message cmd REG_VERIFY_RSP, unreg peer m_local_key != key_u32");
            connection->close();

            return;
        }
            
        m_timer_ctl.del_timer(peer_unreg->m_timer_id);
        lock.lock();
        m_unreg_peers.erase(id_u64);
        m_peers.insert(std::make_pair(id_u64, peer_unreg));
        connection->close();
    }
    else
    {
        connection->close();
    }
}

void Node::close(std::shared_ptr<fly::net::Connection<Json>> connection)
{
    uint64 conn_id = connection->id();
    LOG_INFO("close connection from %s:%d", connection->peer_addr().m_host.c_str(), connection->peer_addr().m_port);
    //std::lock_guard<std::mutex> guard(m_mutex);
    //m_connections.erase(connection->id());
    LOG_INFO("connection count: %u", m_peers.size());
}
    
void Node::be_closed(std::shared_ptr<fly::net::Connection<Json>> connection)
{
    LOG_INFO("connection from %s:%d be closed", connection->peer_addr().m_host.c_str(), connection->peer_addr().m_port);
    //std::lock_guard<std::mutex> guard(m_mutex);
    //m_connections.erase(connection->id());
    LOG_INFO("connection count: %u", m_peers.size());
}

bool Node::insert_peer_score(const std::shared_ptr<Peer_Score> &peer_score)
{
    m_peer_scores.insert(peer_score);
}

bool Node::erase_peer_score(const std::shared_ptr<Peer_Score> &peer_score)
{
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
