#include <unistd.h>
#include "fly/base/logger.hpp"
#include "net/api/wsock_node.hpp"
#include "net/api/message.hpp"
#include "blockchain.hpp"
#include "version.hpp"

using namespace std::placeholders;

namespace net {
namespace api {

Wsock_Node::Wsock_Node()
{
}

Wsock_Node::~Wsock_Node()
{
}

bool Wsock_Node::start(std::string host, uint16 port)
{
    int32 cpu_num = sysconf(_SC_NPROCESSORS_ONLN);
    cpu_num = cpu_num < 4 ? 4 : cpu_num;
    std::unique_ptr<fly::net::Server<Wsock>> server(new fly::net::Server<Wsock>(fly::net::Addr(host, port),
                                                                                std::bind(&Wsock_Node::init, this, _1),
                                                                                std::bind(&Wsock_Node::dispatch, this, _1),
                                                                                std::bind(&Wsock_Node::close, this, _1),
                                                                                std::bind(&Wsock_Node::be_closed, this, _1),
                                                                                cpu_num, 1024 * 1024)); // todo, max_msg_length
    if(server->start())
    {
        CONSOLE_LOG_INFO("start websocket node success");
        m_server = std::move(server);
        std::thread timer_thread(std::bind(&Wsock_Node::timer_proc, this));
        m_timer_thread = std::move(timer_thread);
        
        return true;
    }

    CONSOLE_LOG_FATAL("start websocket node failed!");

    return false;
}

void Wsock_Node::timer_proc()
{
    while(!m_stop.load(std::memory_order_relaxed))
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        m_timer_ctl.run();
    }
}

void Wsock_Node::stop()
{
    m_stop.store(true, std::memory_order_relaxed);
    m_server->stop();
    CONSOLE_LOG_INFO("stop websocket node success");
}

void Wsock_Node::wait()
{
    m_timer_thread.join();
    m_server->wait();
}

void Wsock_Node::set_max_conn(uint32 num)
{
    m_max_conn = num;
}

bool Wsock_Node::init(std::shared_ptr<fly::net::Connection<Wsock>> connection)
{
    auto user = std::make_shared<User>();
    user->m_connection = connection;
    std::unique_lock<std::mutex> lock(m_mutex);
    m_users[connection->id()] = user;
    LOG_DEBUG_INFO("connection count: %u", m_users.size());
    lock.unlock();
    user->m_timer_id = m_timer_ctl.add_timer([=]() {
            connection->close();
        }, 60, true);
    return true;
}

void Wsock_Node::dispatch(std::unique_ptr<fly::net::Message<Wsock>> message)
{
    std::shared_ptr<fly::net::Connection<Wsock>> connection = message->get_connection();
    const fly::net::Addr &addr = connection->peer_addr();
    LOG_DEBUG_INFO("recv message from %s:%d raw_data: %s", addr.m_host.c_str(), addr.m_port, message->raw_data().c_str());
    uint64 conn_id = connection->id();
    uint32 type = message->type();
    uint32 cmd = message->cmd();
    uint32 msg_length = message->length(); // todo, the following cmd need check length
    std::unique_lock<std::mutex> lock(m_mutex);
    
    if(type == MSG_SYS)
    {
        if(cmd == SYS_PING)
        {
            auto user = m_users[conn_id];
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
            m_timer_ctl.reset_timer(user->m_timer_id);
        }
        else if(cmd == SYS_INFO)
        {
            rapidjson::Document doc;
            doc.SetObject();
            rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
            doc.AddMember("msg_type", MSG_SYS, allocator);
            doc.AddMember("msg_cmd", SYS_INFO, allocator);
            doc.AddMember("utc", time(NULL), allocator);
            doc.AddMember("version", ASKCOIN_VERSION, allocator);
            connection->send(doc);
        }
        else
        {
            connection->close();
        }
    }
    else if(type == MSG_ACCOUNT || type == MSG_TX || type == MSG_BLOCK || type == MSG_TOPIC)
    {
        Blockchain::instance()->dispatch_wsock_message(std::move(message));
    }
    else
    {
        connection->close();
    }
}

void Wsock_Node::close(std::shared_ptr<fly::net::Connection<Wsock>> connection)
{
    LOG_DEBUG_INFO("close connection from %s:%d", connection->peer_addr().m_host.c_str(), connection->peer_addr().m_port);
    uint64 conn_id = connection->id();
    std::unique_lock<std::mutex> lock(m_mutex);
    auto user = m_users[conn_id];
    m_timer_ctl.del_timer(user->m_timer_id);
    m_users.erase(conn_id);
    LOG_DEBUG_INFO("connection count: %u", m_users.size());
}

void Wsock_Node::be_closed(std::shared_ptr<fly::net::Connection<Wsock>> connection)
{
    LOG_DEBUG_INFO("connection from %s:%d be closed", connection->peer_addr().m_host.c_str(), connection->peer_addr().m_port);
    uint64 conn_id = connection->id();
    std::unique_lock<std::mutex> lock(m_mutex);
    auto user = m_users[conn_id];
    m_timer_ctl.del_timer(user->m_timer_id);
    m_users.erase(conn_id);
    LOG_DEBUG_INFO("connection count: %u", m_users.size());
}

}
}

void Blockchain::do_wsock_message(std::unique_ptr<fly::net::Message<Wsock>> &message)
{
    std::shared_ptr<fly::net::Connection<Wsock>> connection = message->get_connection();
    const fly::net::Addr &addr = connection->peer_addr();
    uint64 conn_id = connection->id();
    uint32 type = message->type();
    uint32 cmd = message->cmd();
    uint32 msg_length = message->length(); // todo, the following cmd need check length

    if(type == net::api::MSG_ACCOUNT)
    {
        if(cmd == net::api::ACCOUNT_TOP100)
        {
            rapidjson::Document doc;
            doc.SetObject();
            rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
            doc.AddMember("msg_type", net::api::MSG_ACCOUNT, allocator);
            doc.AddMember("msg_cmd", net::api::ACCOUNT_TOP100, allocator);
            doc.AddMember("utc", time(NULL), allocator);
            uint32 cnt = 0;
            rapidjson::Value top_list(rapidjson::kArrayType);
            
            for(auto iter = m_account_by_rich.begin(); iter != m_account_by_rich.end(); ++iter)
            {
                if(++cnt > 100)
                {
                    break;
                }

                
            }
            
            connection->send(doc);
        }
        else if(cmd == net::api::ACCOUNT_NEW)
        {
        }
        else if(cmd == net::api::ACCOUNT_LOGIN)
        {
        }
        else
        {
            connection->close();
        }
    }
    else if(type == net::api::MSG_TX)
    {
    }
    else if(type == net::api::MSG_BLOCK)
    {
    }
    else if(type == net::api::MSG_TOPIC)
    {
    }
}
