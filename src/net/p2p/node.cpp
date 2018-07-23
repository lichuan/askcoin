#include <unistd.h>
#include <chrono>
#include "fly/base/logger.hpp"
#include "fly/net/server.hpp"
#include "fly/net/client.hpp"
#include "net/p2p/node.hpp"
#include "message.hpp"
#include "version.hpp"
#include "blockchain.hpp"
#include "utilstrencodings.h"

using namespace std::placeholders;

namespace net {
namespace p2p {

Node::Node()
{
}

Node::~Node()
{
}

bool Node::start(uint16 port)
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
                                                                              m_poller, 1024 * 1024)); // todo, max_msg_length?
    m_poller->start();
    m_port = port;
    
    if(server->start())
    {
        CONSOLE_LOG_INFO("start p2p node success");
        m_server = std::move(server);
        std::thread timer_thread(std::bind(&Node::timer_proc, this));
        m_timer_thread = std::move(timer_thread);
        std::thread connect_thread(std::bind(&Node::connect_proc, this));
        m_connect_thread = std::move(connect_thread);
        
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

void Node::timer_proc()
{
    while(!m_stop.load(std::memory_order_relaxed))
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        m_timer_ctl.run();
    }
}

void Node::connect_proc()
{
    while(!m_stop.load(std::memory_order_relaxed))
    {
        uint32 peer_num = 0;
        {
            std::lock_guard<std::mutex> guard(m_peer_mutex);
            peer_num = m_peers.size() + m_unreg_peers.size();
        }
        
        if(peer_num >= m_max_conn)
        {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            
            continue;
        }
        
        std::unique_lock<std::mutex> lock(m_score_mutex);
        bool iter_all = true;

        for(auto iter = m_peer_scores.begin(); iter != m_peer_scores.end(); ++iter)
        {
            std::shared_ptr<Peer_Score> peer_score = *iter;
            uint8 expect = 0;

            if(m_banned_peers.find(peer_score->key()) != m_banned_peers.end())
            {
                LOG_DEBUG_INFO("try to connect banned peer %s, skipped", peer_score->key().c_str());

                continue;
            }
            
            if(peer_score->m_state.compare_exchange_strong(expect, 1))
            {
                iter_all = false;
                lock.unlock();
                const fly::net::Addr &addr = peer_score->addr();
                std::unique_ptr<fly::net::Client<Json>> client(new fly::net::Client<Json>(addr,
                                                                                          std::bind(&Node::init, this, _1),
                                                                                          std::bind(&Node::dispatch, this, _1),
                                                                                          std::bind(&Node::close, this, _1),
                                                                                          std::bind(&Node::be_closed, this, _1),
                                                                                          m_poller, 1024 * 1024)); // todo, max_msg_length
                LOG_DEBUG_INFO("try to connect peer from peer_score %s", peer_score->key().c_str());

                if(client->connect(1000))
                {
                    LOG_DEBUG_INFO("connect to peer (%s:%u) success", addr.m_host.c_str(), addr.m_port);
                }
                else
                {
                    LOG_DEBUG_ERROR("connect to peer (%s:%u) failed", addr.m_host.c_str(), addr.m_port);
                    peer_score->m_state.store(0, std::memory_order_relaxed);
                    lock.lock();
                    peer_score->sub_score(10);
                }

                break;
            }
        }

        if(iter_all)
        {
            lock.unlock();
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }
}

void Node::wait()
{
    m_timer_thread.join();
    m_connect_thread.join();
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

uint32 Node::get_max_conn()
{
    return m_max_conn;
}

bool Node::allow(std::shared_ptr<fly::net::Connection<Json>> connection)
{
    uint32 peer_num = 0;
    {
        std::lock_guard<std::mutex> guard(m_peer_mutex);
        peer_num = m_peers.size() + m_unreg_peers.size();
    }
    
    if(peer_num > m_max_conn)
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
        LOG_DEBUG_ERROR("init_verify unreg peer doesn't exist");
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
        peer->m_addr = connection->peer_addr();
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
    uint32 type = message->type();
    uint32 cmd = message->cmd();
    uint32 msg_length = message->length(); // todo, the following cmd need check length 
    
    if(iter_reg != m_peers.end())
    {
        std::shared_ptr<Peer> peer = iter_reg->second;
        lock.unlock();

        if(type != MSG_SYS)
        {
            Blockchain::instance()->dispatch_peer_message(std::move(message));
        }
        else
        {
            if(cmd == SYS_PING)
            {
                if(!connection->is_passive())
                {
                    connection->close();
                }
                else
                {
                    static bool pong_doc = false;
                    static rapidjson::Document doc;

                    if(!pong_doc)
                    {
                        doc.SetObject();
                        rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
                        doc.AddMember("msg_type", MSG_SYS, allocator);
                        doc.AddMember("msg_cmd", SYS_PONG, allocator);
                        pong_doc = true;
                    }
                    
                    connection->send(doc);
                    m_timer_ctl.reset_timer(peer->m_timer_id);
                }
            }
            else if(cmd == SYS_PONG)
            {
                if(connection->is_passive())
                {
                    connection->close();
                }
                else
                {
                    m_timer_ctl.reset_timer(peer->m_timer_id);
                }
            }
            else
            {
                connection->close();
            }
        }
        
        return;
    }

    auto iter_unreg = m_unreg_peers.find(conn_id);
    
    if(iter_unreg == m_unreg_peers.end())
    {
        LOG_DEBUG_ERROR("unreg peer doesn't exist");
        connection->close();
        
        return;
    }
    
    std::shared_ptr<Peer> peer = iter_unreg->second;
    lock.unlock();
    
    if(type != MSG_REG)
    {
        LOG_DEBUG_ERROR("unreg peer recv message type: %u not MSG_REG", type);
        connection->close();
        
        return;
    }

    rapidjson::Document& doc = message->doc();

    if(!connection->is_passive())
    {
        if(cmd == REG_RSP)
        {
            if(peer->m_state != 1)
            {
                LOG_DEBUG_ERROR("unreg peer recv message REG_RSP, but m_state is not 1");
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
            LOG_DEBUG_INFO("unreg peer (m_state:1) recv message cmd REG_RSP, version:%u, id:%lu, key:%u from %s:%u", version_u32, id_u64, key_u32, \
                     connection->peer_addr().m_host.c_str(), connection->peer_addr().m_port);
            
            if(!version_compatible(version_u32, ASKCOIN_VERSION))
            {
                LOG_DEBUG_ERROR("unreg peer (m_state:1) !version_compatible(%u,%u), addr: %s", version_u32, ASKCOIN_VERSION, peer->key().c_str());
                connection->close();

                return;
            }

            peer->m_remote_key = key_u32;
            peer->m_reg_conn_id = id_u64;
            peer->m_state = 3;
        }
        else if(cmd == REG_VERIFY_RSP)
        {
            if(peer->m_state != 0)
            {
                LOG_DEBUG_ERROR("verify unreg peer recv message REG_VERIFY_RSP, but m_state is not 0");
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
            LOG_DEBUG_INFO("verify unreg peer (m_state:0) recv message cmd REG_VERIFY_RSP, id:%lu, key:%u", id_u64, key_u32);
            std::unique_lock<std::mutex> lock(m_peer_mutex);
            auto iter_unreg = m_unreg_peers.find(id_u64);

            if(iter_unreg == m_unreg_peers.end())
            {
                LOG_DEBUG_ERROR("after recv message cmd REG_VERIFY_RSP, unreg peer doesn't exist");
                connection->close();
        
                return;
            }

            std::shared_ptr<Peer> peer_unreg = iter_unreg->second;

            if(peer_unreg->m_state != 4)
            {
                LOG_DEBUG_ERROR("after recv message cmd REG_VERIFY_RSP, unreg peer m_state != 4");
                connection->close();
            
                return;
            }
        
            if(key_u32 != peer_unreg->m_local_key)
            {
                LOG_DEBUG_ERROR("after recv message cmd REG_VERIFY_RSP, unreg peer m_local_key != key_u32");
                connection->close();

                return;
            }
        
            m_unreg_peers.erase(id_u64);
            m_peers.insert(std::make_pair(id_u64, peer_unreg));
            m_timer_ctl.reset_timer(peer_unreg->m_timer_id);
            lock.unlock();
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
            LOG_DEBUG_ERROR("unreg peer recv message REG_REQ, but m_state is not 0");
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
        uint16 port_u16 = port.GetUint();
        uint32 key_u32 = key.GetUint();
        LOG_DEBUG_INFO("unreg peer (m_state:0) recv message cmd REG_REQ, version:%u, id:%lu, key:%u, host:%s, port:%u", version_u32, id_u64, key_u32, host_str.c_str(), port_u16);
        if(!version_compatible(version_u32, ASKCOIN_VERSION))
        {
            LOG_DEBUG_ERROR("unreg peer (m_state:0) !version_compatible(%u,%u), addr: %s:%u", version_u32, ASKCOIN_VERSION, host_str.c_str(), port_u16);
            connection->close();
            
            return;
        }
        
        peer->m_local_key = fly::base::random_32();
        peer->m_remote_key = key_u32;
        peer->m_reg_conn_id = id_u64;
        peer->m_addr = fly::net::Addr(host_str, port_u16);
        std::shared_ptr<Peer_Score> peer_score = std::make_shared<Peer_Score>(peer->m_addr);
        std::unique_lock<std::mutex> lock(m_score_mutex);
        
        if(m_banned_peers.find(peer_score->key()) != m_banned_peers.end())
        {
            LOG_DEBUG_ERROR("unreg peer (m_state:0) is banned, addr: %s:%u", host_str.c_str(), port_u16);
            connection->close();
            
            return;
        }
        
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
        uint8 expect = 0;

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

            std::thread tmp_thread([=, &lock]() {
                    std::unique_ptr<fly::net::Client<Json>> client(new fly::net::Client<Json>(peer->m_addr,
                                                                                              std::bind(&Node::init_verify, this, _1, conn_id),
                                                                                              std::bind(&Node::dispatch, this, _1),
                                                                                              std::bind(&Node::close, this, _1),
                                                                                              std::bind(&Node::be_closed, this, _1),
                                                                                              m_poller));
                    if(client->connect(1000))
                    {
                        LOG_DEBUG_INFO("unreg peer (m_state:2) connect to peer (%s:%u) success", peer->m_addr.m_host.c_str(), peer->m_addr.m_port);
                    }
                    else
                    {
                        LOG_DEBUG_ERROR("unreg peer (m_state:2) connect to peer (%s:%u) failed", peer->m_addr.m_host.c_str(), peer->m_addr.m_port);
                        connection->close();
                        lock.lock();
                        peer_score->sub_score(100);
                    }
                });
            tmp_thread.detach();
        }
        else
        {
            LOG_DEBUG_ERROR("peer (%s) already registered, so close request connection", peer_score->key().c_str());
            connection->close();
        }
    }
    else if(cmd == REG_VERIFY_REQ)
    {
        if(peer->m_state != 0)
        {
            LOG_DEBUG_ERROR("verify unreg peer recv message REG_VERIFY_REQ, but m_state is not 0");
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
        LOG_DEBUG_INFO("verify unreg peer (m_state:0) recv message cmd REG_VERIFY_REQ, id:%lu, key:%u", id_u64, key_u32);
        std::unique_lock<std::mutex> lock(m_peer_mutex);
        auto iter_unreg = m_unreg_peers.find(id_u64);

        if(iter_unreg == m_unreg_peers.end())
        {
            LOG_DEBUG_ERROR("after recv message cmd REG_VERIFY_REQ, unreg peer doesn't exist");
            connection->close();
        
            return;
        }

        std::shared_ptr<Peer> peer_unreg = iter_unreg->second;

        if(peer_unreg->m_state != 3)
        {
            LOG_DEBUG_ERROR("after recv message cmd REG_VERIFY_REQ, unreg peer m_state != 3");
            connection->close();
            
            return;
        }

        if(key_u32 != peer_unreg->m_local_key)
        {
            LOG_DEBUG_ERROR("after recv message cmd REG_VERIFY_REQ, unreg peer m_local_key != key_u32");
            connection->close();

            return;
        }

        m_unreg_peers.erase(id_u64);
        m_peers.insert(std::make_pair(id_u64, peer_unreg));
        m_timer_ctl.reset_timer(peer_unreg->m_timer_id);
        std::shared_ptr<fly::net::Connection<Json>> reg_connection = peer_unreg->m_connection;
        peer_unreg->m_ping_timer_id = m_timer_ctl.add_timer([=]() {
                static bool ping_doc = false;
                static rapidjson::Document doc;

                if(!ping_doc)
                {
                    doc.SetObject();
                    rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
                    doc.AddMember("msg_type", MSG_SYS, allocator);
                    doc.AddMember("msg_cmd", SYS_PING, allocator);
                    ping_doc = true;
                }

                reg_connection->send(doc);
            }, 5);
        lock.unlock();
        rapidjson::Document doc;
        doc.SetObject();
        rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
        doc.AddMember("msg_type", MSG_REG, allocator);
        doc.AddMember("msg_cmd", REG_VERIFY_RSP, allocator);
        doc.AddMember("key", peer_unreg->m_remote_key, allocator);
        doc.AddMember("id", peer_unreg->m_reg_conn_id, allocator);
        connection->send(doc);
    }
    else
    {
        connection->close();
    }
}

void Node::close(std::shared_ptr<fly::net::Connection<Json>> connection)
{
    uint64 conn_id = connection->id();
    std::unique_lock<std::mutex> lock(m_peer_mutex);
    auto iter_reg = m_peers.find(conn_id);
    auto iter_unreg = m_unreg_peers.find(conn_id);
    std::shared_ptr<Peer> peer;
    LOG_DEBUG_INFO("close connection from %s:%d", connection->peer_addr().m_host.c_str(), connection->peer_addr().m_port);
    
    if(iter_reg == m_peers.end())
    {
        peer = iter_unreg->second;
        m_unreg_peers.erase(conn_id);
        
        if(peer->m_state == 0)
        {
            LOG_DEBUG_INFO("unreg peer (m_state:0) close");

            return;
        }
        
        LOG_DEBUG_INFO("unreg peer (%s) close", peer->key().c_str());
    }
    else
    {
        peer = iter_reg->second;
        LOG_DEBUG_INFO("reg peer (%s) close", peer->key().c_str());
        m_peers.erase(conn_id);
    }

    lock.unlock();
    m_timer_ctl.del_timer(peer->m_timer_id);
    m_timer_ctl.del_timer(peer->m_ping_timer_id);
    std::lock_guard<std::mutex> guard(m_score_mutex);
    auto iter_score = m_peer_score_map.find(peer->key());
    
    if(iter_score == m_peer_score_map.end())
    {
        return;
    }

    std::shared_ptr<Peer_Score> peer_score = iter_score->second;
    peer_score->sub_score(1);
    peer_score->m_state.store(0, std::memory_order_relaxed);
}

void Node::be_closed(std::shared_ptr<fly::net::Connection<Json>> connection)
{
    uint64 conn_id = connection->id();
    std::unique_lock<std::mutex> lock(m_peer_mutex);
    auto iter_reg = m_peers.find(conn_id);
    auto iter_unreg = m_unreg_peers.find(conn_id);
    std::shared_ptr<Peer> peer;
    LOG_DEBUG_INFO("close connection from %s:%d be closed", connection->peer_addr().m_host.c_str(), connection->peer_addr().m_port);
    
    if(iter_reg == m_peers.end())
    {
        peer = iter_unreg->second;
        m_unreg_peers.erase(conn_id);
        
        if(peer->m_state == 0)
        {
            LOG_DEBUG_INFO("unreg peer (m_state:0) be closed");

            return;
        }
        
        LOG_DEBUG_INFO("unreg peer (%s) be closed", peer->key().c_str());
    }
    else
    {
        peer = iter_reg->second;
        LOG_DEBUG_INFO("reg peer (%s) be closed", peer->key().c_str());
        m_peers.erase(conn_id);
    }

    lock.unlock();
    m_timer_ctl.del_timer(peer->m_timer_id);
    m_timer_ctl.del_timer(peer->m_ping_timer_id);
    std::lock_guard<std::mutex> guard(m_score_mutex);
    auto iter_score = m_peer_score_map.find(peer->key());
    
    if(iter_score == m_peer_score_map.end())
    {
        return;
    }
    
    std::shared_ptr<Peer_Score> peer_score = iter_score->second;
    peer_score->sub_score(1);
    peer_score->m_state.store(0, std::memory_order_relaxed);
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
            m_peer_scores.erase(iter);
            
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
    
    if(m_peer_score_map.find(key) == m_peer_score_map.end())
    {
        return false;
    }
    
    m_peer_score_map.erase(key);
    auto iter_end = m_peer_scores.upper_bound(peer_score);
    
    for(auto iter = m_peer_scores.lower_bound(peer_score); iter != iter_end; ++iter)
    {
        if(*iter == peer_score)
        {
            m_peer_scores.erase(iter);
            
            return true;
        }
    }

    return false;
}

}
}

void Blockchain::punish_peer(std::shared_ptr<net::p2p::Peer> peer)
{
    net::p2p::Node *p2p_node = net::p2p::Node::instance();
    std::unordered_map<std::string, std::shared_ptr<net::p2p::Peer_Score>> &peer_score_map = p2p_node->m_peer_score_map;
    peer->m_connection->close();
    {
        std::lock_guard<std::mutex> guard(p2p_node->m_score_mutex);
        auto iter_score = peer_score_map.find(peer->key());
        
        if(iter_score == peer_score_map.end())
        {
            return;
        }

        LOG_DEBUG_INFO("punish_peer + banned, peer: %s", peer->key().c_str());
        std::shared_ptr<net::p2p::Peer_Score> peer_score = iter_score->second;
        peer_score->sub_score(1000);
        p2p_node->m_banned_peers.insert(peer->key());
        p2p_node->m_timer_ctl.add_timer([=]() {
                std::lock_guard<std::mutex> guard(p2p_node->m_score_mutex);
                p2p_node->m_banned_peers.erase(peer->key());
                LOG_DEBUG_INFO("unbanned peer: %s", peer->key().c_str());
            }, 600, true);
    }
}

void Blockchain::do_peer_message(std::unique_ptr<fly::net::Message<Json>> &message)
{
    std::shared_ptr<fly::net::Connection<Json>> connection = message->get_connection();
    uint64 conn_id = connection->id();
    uint32 type = message->type();
    uint32 cmd = message->cmd();
    net::p2p::Node *p2p_node = net::p2p::Node::instance();
    std::unordered_map<uint64, std::shared_ptr<net::p2p::Peer>> &peers = p2p_node->m_peers;
    std::unique_lock<std::mutex> lock(p2p_node->m_peer_mutex);
    auto iter_reg = peers.find(conn_id);

    if(iter_reg == peers.end())
    {
        return;
    }

    std::shared_ptr<net::p2p::Peer> peer = iter_reg->second;
    lock.unlock();

    if(peer->m_connection != connection)
    {
        LOG_FATAL("do_peer_message, peer->m_connection != connection, peer key: %s", peer->key().c_str());

        return;
    }
    
    rapidjson::Document& doc = message->doc();
    uint32 msg_length = message->length(); // todo, the following need check length
    LOG_DEBUG_INFO("peer msg: %s, length: %u, peer key: %s", message->raw_data().c_str(), msg_length, peer->key().c_str());
    
    if(type == net::p2p::MSG_BLOCK)
    {
        if(cmd == net::p2p::BLOCK_BROADCAST)
        {
            if(m_pending_peer_keys.find(peer->key()) != m_pending_peer_keys.end())
            {
                return;
            }

            if(!doc.HasMember("block"))
            {
                punish_peer(peer);

                return;
            }
            
            const rapidjson::Value &block = doc["block"];

            if(!block.IsObject())
            {
                punish_peer(peer);

                return;
            }

            if(!block.HasMember("hash"))
            {
                punish_peer(peer);

                return;
            }

            if(!block.HasMember("sign"))
            {
                punish_peer(peer);

                return;
            }

            if(!block["hash"].IsString())
            {
                punish_peer(peer);

                return;
            }

            if(!block["sign"].IsString())
            {
                punish_peer(peer);

                return;
            }

            std::string block_hash = block["hash"].GetString();
            std::string block_sign = block["sign"].GetString();

            if(block_hash.length() != 44)
            {
                punish_peer(peer);
                
                return;
            }

            if(m_blocks.find(block_hash) != m_blocks.end())
            {
                return;
            }

            if(!block.HasMember("pow"))
            {
                punish_peer(peer);

                return;
            }

            const rapidjson::Value &pow_array = block["pow"];

            if(!pow_array.IsArray())
            {
                punish_peer(peer);

                return;
            }
            
            uint32 pow_num = pow_array.Size();

            if(pow_num != 9)
            {
                punish_peer(peer);
                
                return;
            }

            for(uint32 i = 0; i < 9; ++i)
            {
                if(!pow_array[i].IsUint())
                {
                    punish_peer(peer);
                    
                    return;
                }
            }
            
            Accum_Pow declared_pow(pow_array[0].GetUint(), pow_array[1].GetUint(), pow_array[2].GetUint(), pow_array[3].GetUint(), pow_array[4].GetUint(), \
                                pow_array[5].GetUint(), pow_array[6].GetUint(), pow_array[7].GetUint(), pow_array[8].GetUint());

            // todo, what if is switching?
            if(!m_most_difficult_block->difficult_than_me(declared_pow))
            {
                return;
            }
            
            if(!block.HasMember("data"))
            {
                punish_peer(peer);

                return;
            }
            
            const rapidjson::Value &data = block["data"];

            if(!data.IsObject())
            {
                punish_peer(peer);

                return;
            }

            if(!data.HasMember("id"))
            {
                punish_peer(peer);

                return;
            }

            if(!data["id"].IsUint64())
            {
                punish_peer(peer);

                return;
            }

            uint64 block_id = data["id"].GetUint64();

            if(block_id == 0)
            {
                punish_peer(peer);

                return;
            }

            if(!data.HasMember("utc"))
            {
                punish_peer(peer);

                return;
            }

            if(!data["utc"].IsUint64())
            {
                punish_peer(peer);

                return;
            }

            uint64 utc = data["utc"].GetUint64();

            if(!data.HasMember("version"))
            {
                punish_peer(peer);

                return;
            }

            if(!data["version"].IsUint())
            {
                punish_peer(peer);

                return;
            }

            // todo, version compatible?
            uint32 version = data["version"].GetUint();
            
            if(!data.HasMember("zero_bits"))
            {
                punish_peer(peer);

                return;
            }

            if(!data["zero_bits"].IsUint())
            {
                punish_peer(peer);

                return;
            }

            uint32 zero_bits = data["zero_bits"].GetUint();

            if(zero_bits == 0 || zero_bits > 256)
            {
                punish_peer(peer);
                
                return;
            }
            
            if(!data.HasMember("pre_hash"))
            {
                punish_peer(peer);

                return;
            }

            if(!data["pre_hash"].IsString())
            {
                punish_peer(peer);

                return;
            }

            std::string pre_hash = data["pre_hash"].GetString();

            if(pre_hash.length() != 44)
            {
                punish_peer(peer);

                return;
            }
            
            if(!data.HasMember("miner"))
            {
                punish_peer(peer);

                return;
            }

            if(!data["miner"].IsString())
            {
                punish_peer(peer);

                return;
            }

            std::string miner_pubkey = data["miner"].GetString();

            if(miner_pubkey.length() != 88)
            {
                punish_peer(peer);

                return;
            }

            if(!data.HasMember("nonce"))
            {
                punish_peer(peer);

                return;
            }

            const rapidjson::Value &nonce = data["nonce"];

            if(!nonce.IsArray())
            {
                punish_peer(peer);

                return;
            }

            if(nonce.Size() != 4)
            {
                punish_peer(peer);

                return;
            }
            
            for(uint32 i = 0; i < 4; ++i)
            {
                if(!nonce[i].IsUint64())
                {
                    punish_peer(peer);

                    return;
                }
            }
            
            if(!data.HasMember("tx_ids"))
            {
                punish_peer(peer);

                return;
            }
            
            const rapidjson::Value &tx_ids = data["tx_ids"];

            if(!tx_ids.IsArray())
            {
                punish_peer(peer);

                return;
            }
            
            uint32 tx_num = tx_ids.Size();
            
            if(tx_num > 2000)
            {
                punish_peer(peer);

                return;
            }

            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
            data.Accept(writer);
            std::string data_str(buffer.GetString(), buffer.GetSize());
            std::string block_hash_verify = coin_hash_b64(buffer.GetString(), buffer.GetSize());
            
            if(block_hash != block_hash_verify)
            {
                punish_peer(peer);

                return;
            }

            for(rapidjson::Value::ConstValueIterator iter = tx_ids.Begin(); iter != tx_ids.End(); ++iter)
            {
                std::string tx_id = iter->GetString();
                
                if(tx_id.length() != 44)
                {
                    punish_peer(peer);

                    return;
                }
            }
            
            if(!verify_sign(miner_pubkey, block_hash, block_sign))
            {
                punish_peer(peer);

                return;
            }
            
            if(!verify_hash(block_hash, data_str, zero_bits))
            {
                punish_peer(peer);
                
                return;
            }

            std::shared_ptr<Pending_Block> pending_block;
            auto iter_pending_block = m_pending_blocks.find(block_hash);
            bool is_new_pending_block = false;
            
            if(iter_pending_block != m_pending_blocks.end())
            {
                pending_block = iter_pending_block->second;
            }
            else
            {
                pending_block = std::make_shared<Pending_Block>(block_id, utc, version, zero_bits, block_hash, pre_hash);
                is_new_pending_block = true;
            }
            
            std::shared_ptr<Pending_Chain> pending_chain(new Pending_Chain(peer, pending_block, declared_pow));
            
            if(!pending_chain->m_remain_pow.sub_pow(pending_block->m_zero_bits))
            {
                punish_peer(peer);

                return;
            }
            
            if(is_new_pending_block)
            {
                auto iter_brief_req = m_pending_brief_reqs.find(block_hash);
                
                if(iter_brief_req != m_pending_brief_reqs.end())
                {
                    std::shared_ptr<Pending_Brief_Request> request = iter_brief_req->second;
                    m_timer_ctl.del_timer(request->m_timer_id);
                    m_pending_brief_reqs.erase(block_hash);
                }
                
                m_pending_blocks.insert(std::make_pair(block_hash, pending_block));
                m_pending_block_hashes.push_back(block_hash);
                
                if(m_pending_block_hashes.size() > 1000000)
                {
                    m_pending_blocks.erase(m_pending_block_hashes.front());
                    m_pending_block_hashes.pop_front();
                }
            }
            
            m_pending_peer_keys.insert(peer->key());
            uint64 now = time(NULL);
            
            if(utc > now)
            {
                uint32 diff = utc - now;

                if(diff > 3600)
                {
                    LOG_DEBUG_WARN("block time too future, diff: %u > 3600, hash: %s, peer key: %s", diff, block_hash.c_str(), peer->key().c_str());
                }
                
                m_timer_ctl.add_timer([=]() {
                        m_pending_brief_chains.push_back(pending_chain);
                    }, diff, true);
            }
            else
            {
                m_pending_brief_chains.push_back(pending_chain);
            }
        }
        else if(cmd == net::p2p::BLOCK_BRIEF_RSP)
        {
            if(!doc.HasMember("block"))
            {
                return;
            }
            
            const rapidjson::Value &block = doc["block"];

            if(!block.IsObject())
            {
                return;
            }
            
            if(!block.HasMember("hash"))
            {
                return;
            }

            if(!block.HasMember("sign"))
            {
                return;
            }

            if(!block["hash"].IsString())
            {
                return;
            }

            if(!block["sign"].IsString())
            {
                return;
            }
            
            std::string block_hash = block["hash"].GetString();
            std::string block_sign = block["sign"].GetString();

            if(block_hash.length() != 44)
            {
                return;
            }

            if(m_blocks.find(block_hash) != m_blocks.end())
            {
                return;
            }

            if(m_pending_blocks.find(block_hash) != m_pending_blocks.end())
            {
                return;
            }

            auto iter_brief_req = m_pending_brief_reqs.find(block_hash);
            
            if(iter_brief_req == m_pending_brief_reqs.end())
            {
                return;
            }

            std::shared_ptr<Pending_Brief_Request> request = iter_brief_req->second;

            if(!block.HasMember("data"))
            {
                return;
            }
            
            const rapidjson::Value &data = block["data"];

            if(!data.IsObject())
            {
                return;
            }

            if(!data.HasMember("id"))
            {
                return;
            }

            if(!data["id"].IsUint64())
            {
                return;
            }

            uint64 block_id = data["id"].GetUint64();

            if(block_id == 0)
            {
                return;
            }

            if(!data.HasMember("utc"))
            {
                return;
            }

            if(!data["utc"].IsUint64())
            {
                return;
            }

            uint64 utc = data["utc"].GetUint64();

            if(!data.HasMember("version"))
            {
                return;
            }

            if(!data["version"].IsUint())
            {
                return;
            }
            
            // todo, version compatible?
            uint32 version = data["version"].GetUint();
            
            if(!data.HasMember("zero_bits"))
            {
                return;
            }

            if(!data["zero_bits"].IsUint())
            {
                return;
            }

            uint32 zero_bits = data["zero_bits"].GetUint();

            if(zero_bits == 0 || zero_bits > 256)
            {
                return;
            }
            
            if(!data.HasMember("pre_hash"))
            {
                return;
            }

            if(!data["pre_hash"].IsString())
            {
                return;
            }

            std::string pre_hash = data["pre_hash"].GetString();

            if(pre_hash.length() != 44)
            {
                return;
            }
            
            if(!data.HasMember("miner"))
            {
                return;
            }

            if(!data["miner"].IsString())
            {
                return;
            }

            std::string miner_pubkey = data["miner"].GetString();

            if(miner_pubkey.length() != 88)
            {
                return;
            }

            if(!data.HasMember("nonce"))
            {
                return;
            }

            const rapidjson::Value &nonce = data["nonce"];

            if(!nonce.IsArray())
            {
                return;
            }

            if(nonce.Size() != 4)
            {
                return;
            }
            
            for(uint32 i = 0; i < 4; ++i)
            {
                if(!nonce[i].IsUint64())
                {
                    return;
                }
            }
            
            if(!data.HasMember("tx_ids"))
            {
                return;
            }
            
            const rapidjson::Value &tx_ids = data["tx_ids"];

            if(!tx_ids.IsArray())
            {
                return;
            }
            
            uint32 tx_num = tx_ids.Size();
            
            if(tx_num > 2000)
            {
                return;
            }

            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
            data.Accept(writer);
            std::string data_str(buffer.GetString(), buffer.GetSize());
            std::string block_hash_verify = coin_hash_b64(buffer.GetString(), buffer.GetSize());
            
            if(block_hash != block_hash_verify)
            {
                return;
            }

            for(rapidjson::Value::ConstValueIterator iter = tx_ids.Begin(); iter != tx_ids.End(); ++iter)
            {
                std::string tx_id = iter->GetString();
                
                if(tx_id.length() != 44)
                {
                    return;
                }
            }
            
            if(!verify_sign(miner_pubkey, block_hash, block_sign))
            {
                return;
            }
            
            if(!verify_hash(block_hash, data_str, zero_bits))
            {
                return;
            }
            
            auto pending_block = std::make_shared<Pending_Block>(block_id, utc, version, zero_bits, block_hash, pre_hash);
            m_pending_blocks.insert(std::make_pair(block_hash, pending_block));
            m_pending_block_hashes.push_back(block_hash);

            if(m_pending_block_hashes.size() > 1000000)
            {
                m_pending_blocks.erase(m_pending_block_hashes.front());
                m_pending_block_hashes.pop_front();
            }

            m_timer_ctl.del_timer(request->m_timer_id);
            m_pending_brief_reqs.erase(block_hash);
        }
        else
        {
            punish_peer(peer);
        }
    }
    else if(type == net::p2p::MSG_TX)
    {
    }
    else if(type == net::p2p::MSG_PROBE)
    {
    }
    else
    {
        punish_peer(peer);
    }
}

void Blockchain::do_brief_chain()
{
    std::set<std::string> failed_brief_reqs;
    
    for(auto iter = m_pending_brief_chains.begin(); iter != m_pending_brief_chains.end();)
    {
        std::shared_ptr<Pending_Chain> pending_chain = *iter;
        std::shared_ptr<net::p2p::Peer> peer = pending_chain->m_peer;
        bool continue_if = false;

        if(!m_most_difficult_block->difficult_than_me(pending_chain->m_declared_pow))
        {
            iter = m_pending_brief_chains.erase(iter);
            m_pending_peer_keys.erase(peer->key());

            continue;
        }
        
        while(true)
        {
            std::shared_ptr<Pending_Block> pending_block = pending_chain->m_req_blocks.front();
            std::string pre_hash = pending_block->m_pre_hash;
            auto iter_1 = m_blocks.find(pre_hash);
            
            if(iter_1 != m_blocks.end())
            {
                std::shared_ptr<Block> pre_block = iter_1->second;
                iter = m_pending_brief_chains.erase(iter);
                continue_if = true;

                if(pending_block->m_id != pre_block->id() + 1)
                {
                    punish_peer(peer);
                    m_pending_peer_keys.erase(peer->key());

                    break;
                }
                
                if(!pre_block->difficult_equal(pending_chain->m_remain_pow))
                {
                    punish_peer(peer);
                    m_pending_peer_keys.erase(peer->key());

                    break;
                }
                
                m_brief_chains.push_back(pending_chain);
                
                break;
            }

            // pre_hash(gensis block) should be in m_blocks
            if(pending_block->m_id == 1)
            {
                punish_peer(peer);
                m_pending_peer_keys.erase(peer->key());
                iter = m_pending_brief_chains.erase(iter);
                continue_if = true;
                
                break;
            }
            
            auto iter_2 = m_pending_blocks.find(pre_hash);
            
            if(iter_2 != m_pending_blocks.end())
            {
                std::shared_ptr<Pending_Block> pre_pending_block = iter_2->second;

                if(pending_block->m_id != pre_pending_block->m_id + 1)
                {
                    punish_peer(peer);
                    m_pending_peer_keys.erase(peer->key());
                    iter = m_pending_brief_chains.erase(iter);
                    continue_if = true;
                    
                    break;
                }
                
                if(!pending_chain->m_remain_pow.sub_pow(pre_pending_block->m_zero_bits))
                {
                    punish_peer(peer);
                    m_pending_peer_keys.erase(peer->key());
                    iter = m_pending_brief_chains.erase(iter);
                    continue_if = true;
                    
                    break;
                }

                pending_chain->m_req_blocks.push_front(pre_pending_block);
                pending_chain->m_requested = false;
            }
            else
            {
                std::shared_ptr<Pending_Brief_Request> request;
                auto iter_3 = m_pending_brief_reqs.find(pre_hash);
                
                if(iter_3 == m_pending_brief_reqs.end())
                {
                    request = std::make_shared<Pending_Brief_Request>();
                    request->m_peers.push_back(pending_chain->m_peer);
                    pending_chain->m_requested = true;
                    rapidjson::Document doc;
                    doc.SetObject();
                    rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
                    doc.AddMember("msg_type", net::p2p::MSG_BLOCK, allocator);
                    doc.AddMember("msg_cmd", net::p2p::BLOCK_BRIEF_REQ, allocator);
                    doc.AddMember("hash", rapidjson::StringRef(pre_hash.c_str()), allocator);
                    request->m_peers[0]->m_connection->send(doc);
                    request->m_timer_id = m_timer_ctl.add_timer([=]() {
                            if(request->m_try_num > request->m_peers.size() * 2)
                            {
                                request->m_state = 1;
                                m_timer_ctl.del_timer(request->m_timer_id);
                            }
                            else
                            {
                                auto last_peer = request->m_peers[request->m_last_idx];
                                
                                if(last_peer->m_connection->closed())
                                {
                                    request->del_peer(last_peer);
                                }
                                
                                if(request->m_peers.empty())
                                {
                                    request->m_state = 1;
                                    m_timer_ctl.del_timer(request->m_timer_id);
                                    
                                    return;
                                }
                                
                                rapidjson::Document doc;
                                doc.SetObject();
                                rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
                                doc.AddMember("msg_type", net::p2p::MSG_BLOCK, allocator);
                                doc.AddMember("msg_cmd", net::p2p::BLOCK_BRIEF_REQ, allocator);
                                doc.AddMember("hash", rapidjson::StringRef(pre_hash.c_str()), allocator);
                                uint32 idx = fly::base::random_between(0, request->m_peers.size() - 1);
                                request->m_peers[idx]->m_connection->send(doc);
                                request->m_last_idx = idx;
                                ++request->m_try_num;
                            }
                        }, 1);
                }
                else
                {
                    request = iter_3->second;
                }
                
                if(request->m_state == 1) // failed
                {
                    failed_brief_reqs.insert(pre_hash);

                    if(pending_chain->m_requested)
                    {
                        punish_peer(peer);
                        m_pending_peer_keys.erase(peer->key());
                        iter = m_pending_brief_chains.erase(iter);
                        continue_if = true;
                    }
                }
                else if(!pending_chain->m_requested)
                {
                    request->m_peers.push_back(pending_chain->m_peer);
                    pending_chain->m_requested = true;
                }
                
                break;
            }
        }
        
        if(continue_if)
        {
            continue;
        }
        else
        {
            ++iter;
        }
    }

    for(auto &req_hash : failed_brief_reqs)
    {
        m_pending_brief_reqs.erase(req_hash);
    }

    if(m_is_switching)
    {
        return;
    }
    
    std::shared_ptr<Pending_Chain> most_difficult_chain = std::make_shared<Pending_Chain>();
    Accum_Pow zero_pow;
    
    for(auto iter = m_brief_chains.begin(); iter != m_brief_chains.end();)
    {
        auto &pending_chain = *iter;

        if(!m_most_difficult_block->difficult_than_me(pending_chain->m_declared_pow))
        {
            iter = m_brief_chains.erase(iter);
            m_pending_peer_keys.erase(pending_chain->m_peer->key());
            
            continue;
        }

        if(pending_chain->m_declared_pow > most_difficult_chain->m_declared_pow)
        {
            most_difficult_chain = pending_chain;
        }

        ++iter;
    }
    
    if(most_difficult_chain->m_declared_pow > zero_pow)
    {
        switch_chain(most_difficult_chain);
    }
}
