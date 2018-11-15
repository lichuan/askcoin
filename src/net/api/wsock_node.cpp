#include <unistd.h>
#include "fly/base/logger.hpp"
#include "net/api/wsock_node.hpp"
#include "net/api/message.hpp"
#include "net/api/err_code.hpp"
#include "net/p2p/node.hpp"
#include "net/p2p/message.hpp"
#include "blockchain.hpp"
#include "version.hpp"
#include "tx/tx.hpp"
#include "utilstrencodings.h"

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

    if(m_users.size() >= m_max_conn)
    {
        return false;
    }

    m_users[connection->id()] = user;
    LOG_DEBUG_INFO("connection count: %u", m_users.size());
    lock.unlock();
    user->m_timer_id = m_timer_ctl.add_timer([=]() {
            connection->close();
        }, 30, true);
    return true;
}

void Wsock_Node::dispatch(std::unique_ptr<fly::net::Message<Wsock>> message)
{
    std::shared_ptr<fly::net::Connection<Wsock>> connection = message->get_connection();
    const fly::net::Addr &addr = connection->peer_addr();
    LOG_DEBUG_INFO("recv wsock message from %s:%d raw_data: %s", addr.m_host.c_str(), addr.m_port, message->raw_data().c_str());
    uint64 conn_id = connection->id();
    uint32 type = message->type();
    uint32 cmd = message->cmd();
    uint32 msg_length = message->length(); // todo, the following cmd need check length
    //std::unique_lock<std::mutex> lock(m_mutex);
    rapidjson::Document& doc = message->doc();
    
    if(!doc.HasMember("msg_id"))
    {
        connection->close();
        ASKCOIN_RETURN;
    }

    if(!doc["msg_id"].IsUint())
    {
        connection->close();
        ASKCOIN_RETURN;
    }
    
    uint32 msg_id = doc["msg_id"].GetUint();
    
    if(type == MSG_SYS)
    {
        if(cmd == SYS_PING)
        {
            auto user = m_users[conn_id];
            rapidjson::Document doc;
            doc.SetObject();
            rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
            doc.AddMember("msg_type", MSG_SYS, allocator);
            doc.AddMember("msg_cmd", SYS_PONG, allocator);
            doc.AddMember("msg_id", msg_id, allocator);
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
            doc.AddMember("msg_id", msg_id, allocator);
            doc.AddMember("utc", time(NULL), allocator);
            doc.AddMember("version", ASKCOIN_VERSION, allocator);
            connection->send(doc);
        }
        else
        {
            connection->close();
        }
    }
    else if(type == MSG_ACCOUNT || type == MSG_TX || type == MSG_TOPIC)
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
    m_users_to_register.erase(user->m_pubkey);
    m_users_by_pubkey.erase(user->m_pubkey);
    LOG_DEBUG_INFO("wsock connection count: %u", m_users.size());
}

void Wsock_Node::be_closed(std::shared_ptr<fly::net::Connection<Wsock>> connection)
{
    LOG_DEBUG_INFO("connection from %s:%d be closed", connection->peer_addr().m_host.c_str(), connection->peer_addr().m_port);
    uint64 conn_id = connection->id();
    std::unique_lock<std::mutex> lock(m_mutex);
    auto user = m_users[conn_id];
    m_timer_ctl.del_timer(user->m_timer_id);
    m_users.erase(conn_id);
    m_users_to_register.erase(user->m_pubkey);
    m_users_by_pubkey.erase(user->m_pubkey);
    LOG_DEBUG_INFO("wsock connection count: %u", m_users.size());
}

}
}

void Blockchain::notify_register_failed(std::string pubkey, uint32 reason)
{
    net::api::Wsock_Node *wsock_node = net::api::Wsock_Node::instance();
    std::unique_lock<std::mutex> lock(wsock_node->m_mutex);
    auto iter = wsock_node->m_users_to_register.find(pubkey);
    
    if(iter == wsock_node->m_users_to_register.end())
    {
        return;
    }

    auto user = iter->second;
    wsock_node->m_users_to_register.erase(iter);
    lock.unlock();
    user->m_state = 0;
    rapidjson::Document doc;
    doc.SetObject();
    rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
    doc.AddMember("msg_type", net::api::MSG_TX, allocator);
    doc.AddMember("msg_cmd", net::api::TX_CMD, allocator);
    doc.AddMember("msg_id", 1, allocator);
    doc.AddMember("type", 1, allocator);

    if(reason == 1)
    {
        doc.AddMember("err_code", net::api::ERR_NAME_EXIST, allocator);
    }
    else if(reason == 2)
    {
        doc.AddMember("err_code", net::api::ERR_SIGN_EXPIRED, allocator);
    }
    
    user->m_connection->send(doc);
}

void Blockchain::notify_register_account(std::shared_ptr<Account> account)
{
    net::api::Wsock_Node *wsock_node = net::api::Wsock_Node::instance();
    std::unique_lock<std::mutex> lock(wsock_node->m_mutex);
    auto iter = wsock_node->m_users_to_register.find(account->pubkey());

    if(iter == wsock_node->m_users_to_register.end())
    {
        return;
    }

    auto user = iter->second;
    wsock_node->m_users_to_register.erase(iter);
    lock.unlock();
    rapidjson::Document doc;
    doc.SetObject();
    rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
    doc.AddMember("msg_type", net::api::MSG_TX, allocator);
    doc.AddMember("msg_cmd", net::api::TX_CMD, allocator);
    doc.AddMember("msg_id", 1, allocator);
    doc.AddMember("type", 1, allocator);
    user->m_connection->send(doc);
}

void Blockchain::broadcast_new_topic(std::shared_ptr<Topic> topic)
{
    net::api::Wsock_Node *wsock_node = net::api::Wsock_Node::instance();
    rapidjson::Document doc;
    doc.SetObject();
    rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
    doc.AddMember("msg_type", net::api::MSG_TOPIC, allocator);
    doc.AddMember("msg_cmd", net::api::TOPIC_LIST, allocator);
    doc.AddMember("msg_id", 0, allocator);
    auto owner = topic->get_owner();
    auto block = topic->m_block;
    uint64 block_id = block->id();
    doc.AddMember("topic_key", rapidjson::StringRef(topic->key().c_str()), allocator);
    doc.AddMember("topic_data", rapidjson::StringRef(topic->m_data.c_str()), allocator);
    doc.AddMember("topic_reward", topic->get_total(), allocator);
    doc.AddMember("block_id", block_id, allocator);
    doc.AddMember("utc", block->utc(), allocator);
    doc.AddMember("id", owner->id(), allocator);
    doc.AddMember("avatar", owner->avatar(), allocator);
    doc.AddMember("name", rapidjson::StringRef(owner->name().c_str()), allocator);
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    doc.Accept(writer);
    std::unique_lock<std::mutex> lock(wsock_node->m_mutex);
    
    for(auto &p : wsock_node->m_users_by_pubkey)
    {
        p.second->m_connection->send(buffer.GetString(), buffer.GetSize());
    }
}

void Blockchain::sync_block()
{
    net::api::Wsock_Node *wsock_node = net::api::Wsock_Node::instance();
    rapidjson::Document doc;
    doc.SetObject();
    rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
    doc.AddMember("msg_type", net::api::MSG_BLOCK, allocator);
    doc.AddMember("msg_cmd", net::api::BLOCK_SYNC, allocator);
    doc.AddMember("msg_id", 0, allocator);
    doc.AddMember("block_id", m_cur_block->id(), allocator);
    doc.AddMember("block_hash", rapidjson::StringRef(m_cur_block->hash().c_str()), allocator);
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    doc.Accept(writer);
    std::unique_lock<std::mutex> lock(wsock_node->m_mutex);
    
    for(auto &p : wsock_node->m_users_by_pubkey)
    {
        p.second->m_connection->send(buffer.GetString(), buffer.GetSize());
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
    rapidjson::Document& doc = message->doc();
    uint32 msg_id = doc["msg_id"].GetUint();
    net::api::Wsock_Node *wsock_node = net::api::Wsock_Node::instance();
    std::unique_lock<std::mutex> lock(wsock_node->m_mutex);
    auto &users = wsock_node->m_users;
    auto iter_user = users.find(conn_id);
    
    if(iter_user == users.end())
    {
        ASKCOIN_RETURN;
    }

    auto user = iter_user->second;
    lock.unlock();
    
    if(type == net::api::MSG_ACCOUNT)
    {
        if(cmd == net::api::ACCOUNT_TOP100)
        {
            if(user->m_state != 2)
            {
                connection->close();
                ASKCOIN_RETURN;
            }
            
            rapidjson::Document doc;
            doc.SetObject();
            rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
            doc.AddMember("msg_type", net::api::MSG_ACCOUNT, allocator);
            doc.AddMember("msg_cmd", net::api::ACCOUNT_TOP100, allocator);
            doc.AddMember("msg_id", msg_id, allocator);
            uint32 cnt = 0;
            rapidjson::Value top_list(rapidjson::kArrayType);
            
            for(auto iter = m_account_by_rich.begin(); iter != m_account_by_rich.end(); ++iter)
            {
                if(++cnt > 100)
                {
                    break;
                }
                
                auto account = *iter;
                rapidjson::Value rich_people(rapidjson::kObjectType);
                rich_people.AddMember("name", rapidjson::StringRef(account->name().c_str()), allocator);
                rich_people.AddMember("id", account->id(), allocator);
                rich_people.AddMember("avatar", account->avatar(), allocator);
                rich_people.AddMember("balance", account->get_balance(), allocator);
                top_list.PushBack(rich_people, allocator);
            }
            
            doc.AddMember("top100", top_list, allocator);
            connection->send(doc);
        }
        else if(cmd == net::api::ACCOUNT_PROBE)
        {
            if(user->m_state != 0)
            {
                connection->close();
                ASKCOIN_RETURN;
            }
            
            if(!doc.HasMember("data"))
            {
                connection->close();
                ASKCOIN_RETURN;
            }
            
            if(!doc["data"].IsObject())
            {
                connection->close();
                ASKCOIN_RETURN;
            }
            
            if(!doc.HasMember("sign"))
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(!doc["sign"].IsString())
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            rapidjson::Value &data = doc["data"];

            if(!data.HasMember("utc"))
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(!data["utc"].IsUint64())
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(!data.HasMember("pubkey"))
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(!data["pubkey"].IsString())
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            std::string pubkey = data["pubkey"].GetString();

            if(!is_base64_char(pubkey))
            {
                connection->close();
                ASKCOIN_RETURN;
            }
            
            if(pubkey.length() != 88)
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(!user->m_reg_probe)
            {
                uint64 utc = data["utc"].GetUint64();
                uint64 utc_now = time(NULL);
                std::string tx_sign = doc["sign"].GetString();
                
                if(utc + 10 < utc_now || utc_now + 10 < utc)
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }
                
                if(!is_base64_char(tx_sign))
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }
                
                rapidjson::StringBuffer buffer;
                rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
                data.Accept(writer);
                std::string tx_id = coin_hash_b64(buffer.GetString(), buffer.GetSize());
            
                if(!verify_sign(pubkey, tx_id, tx_sign))
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }
                
                user->m_pubkey = pubkey;
                user->m_reg_probe = true;
            }
            else
            {
                if(pubkey != user->m_pubkey)
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }
            }
            
            rapidjson::Document doc;
            doc.SetObject();
            rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
            doc.AddMember("msg_type", net::api::MSG_ACCOUNT, allocator);
            doc.AddMember("msg_cmd", net::api::ACCOUNT_PROBE, allocator);
            doc.AddMember("msg_id", msg_id, allocator);
            std::shared_ptr<Account> exist_account;
            
            if(get_account(pubkey, exist_account))
            {
                connection->send(doc);
                user->m_state = 1;
            }
            else if(m_uv_account_pubkeys.find(pubkey) == m_uv_account_pubkeys.end())
            {
                doc.AddMember("err_code", net::api::ERR_REG_FAILED, allocator);
                connection->send(doc);
            }
            else
            {
                doc.AddMember("err_code", net::api::ERR_REG_WAIT, allocator);
                connection->send(doc);
            }
        }
        else if(cmd == net::api::ACCOUNT_INFO)
        {
            if(user->m_state != 2)
            {
                connection->close();
                ASKCOIN_RETURN;
            }
            
            std::shared_ptr<Account> account;
            
            if(!get_account(user->m_pubkey, account))
            {
                connection->close();
                ASKCOIN_RETURN;
            }
            
            rapidjson::Document doc;
            doc.SetObject();
            rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
            doc.AddMember("msg_type", net::api::MSG_ACCOUNT, allocator);
            doc.AddMember("msg_cmd", net::api::ACCOUNT_INFO, allocator);
            doc.AddMember("msg_id", msg_id, allocator);
            doc.AddMember("id", account->id(), allocator);
            doc.AddMember("avatar", account->avatar(), allocator);
            doc.AddMember("balance", account->get_balance(), allocator);
            doc.AddMember("name", rapidjson::StringRef(account->name().c_str()), allocator);
            connection->send(doc);
        }
        else if(cmd == net::api::ACCOUNT_QUERY)
        {
            if(user->m_state != 2)
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(!doc.HasMember("id"))
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(!doc["id"].IsUint64())
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            uint64 account_id = doc["id"].GetUint64();

            if(account_id == 0)
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            rapidjson::Document doc;
            doc.SetObject();
            rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
            doc.AddMember("msg_type", net::api::MSG_ACCOUNT, allocator);
            doc.AddMember("msg_cmd", net::api::ACCOUNT_QUERY, allocator);
            doc.AddMember("msg_id", msg_id, allocator);
            std::shared_ptr<Account> receiver;
            auto iter = m_account_by_id.find(account_id);
            doc.AddMember("id", account_id, allocator);

            if(iter == m_account_by_id.end())
            {
                doc.AddMember("err_code", net::api::ERR_RECEIVER_NOT_EXIST, allocator);
                connection->send(doc);
                ASKCOIN_RETURN;
            }
            
            receiver = iter->second;
            doc.AddMember("avatar", receiver->avatar(), allocator);
            doc.AddMember("name", rapidjson::StringRef(receiver->name().c_str()), allocator);
            doc.AddMember("pubkey", rapidjson::StringRef(receiver->pubkey().c_str()), allocator);
            connection->send(doc);
        }
        else if(cmd == net::api::ACCOUNT_HISTORY)
        {
            if(user->m_state != 2)
            {
                connection->close();
                ASKCOIN_RETURN;
            }
            
            std::shared_ptr<Account> account;
            
            if(!get_account(user->m_pubkey, account))
            {
                connection->close();
                ASKCOIN_RETURN;
            }
            
            account->proc_history_expired(m_cur_block->id());
            rapidjson::Document doc;
            doc.SetObject();
            rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
            doc.AddMember("msg_type", net::api::MSG_ACCOUNT, allocator);
            doc.AddMember("msg_cmd", net::api::ACCOUNT_HISTORY, allocator);
            doc.AddMember("msg_id", msg_id, allocator);
            doc.AddMember("id", account->id(), allocator);
            doc.AddMember("avatar", account->avatar(), allocator);
            doc.AddMember("balance", account->get_balance(), allocator);
            doc.AddMember("name", rapidjson::StringRef(account->name().c_str()), allocator);
            rapidjson::Value history_list(rapidjson::kArrayType);
            
            for(auto history : account->m_history)
            {
                rapidjson::Value obj;
                obj.AddMember("type", history->m_type, allocator);
                obj.AddMember("change", history->m_change, allocator);
                obj.AddMember("target_id", history->m_target_id, allocator);
                obj.AddMember("target_avatar", history->m_target_avatar, allocator);
                obj.AddMember("block_id", history->m_block_id, allocator);
                obj.AddMember("utc", history->m_utc, allocator);
                
                if(!history->m_memo.empty())
                {
                    obj.AddMember("memo", rapidjson::StringRef(history->m_memo.c_str()), allocator);
                }
                
                if(!history->m_target_name.empty())
                {
                    obj.AddMember("target_name", rapidjson::StringRef(history->m_target_name.c_str()), allocator);
                }

                history_list.PushBack(obj, allocator);
            }
            
            doc.AddMember("histories", history_list, allocator);
            connection->send(doc);
        }
        else if(cmd == net::api::ACCOUNT_IMPORT)
        {
            // todo, if the mobile app run background, will socket disconnect ???
            if(user->m_state == 2)
            {
                connection->close();
                ASKCOIN_RETURN;
            }
            
            if(!doc.HasMember("data"))
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(!doc["data"].IsObject())
            {
                connection->close();
                ASKCOIN_RETURN;
            }
            
            if(!doc.HasMember("sign"))
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(!doc["sign"].IsString())
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            rapidjson::Value &data = doc["data"];

            if(!data.HasMember("utc"))
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(!data["utc"].IsUint64())
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(!data.HasMember("pubkey"))
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(!data["pubkey"].IsString())
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            std::string pubkey = data["pubkey"].GetString();
            uint64 utc = data["utc"].GetUint64();
            uint64 utc_now = time(NULL);
            std::string tx_sign = doc["sign"].GetString();
            
            if(utc + 10 < utc_now || utc_now + 10 < utc)
            {
                connection->close();
                ASKCOIN_RETURN;
            }
            
            if(!is_base64_char(pubkey))
            {
                connection->close();
                ASKCOIN_RETURN;
            }
            
            if(pubkey.length() != 88)
            {
                connection->close();
                ASKCOIN_RETURN;
            }
            
            if(!is_base64_char(tx_sign))
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(user->m_state == 1)
            {
                if(user->m_pubkey != pubkey)
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }
            }
            
            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
            data.Accept(writer);
            std::string tx_id = coin_hash_b64(buffer.GetString(), buffer.GetSize());
            
            if(!verify_sign(pubkey, tx_id, tx_sign))
            {
                connection->close();
                ASKCOIN_RETURN;
            }
            
            rapidjson::Document doc;
            doc.SetObject();
            rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
            doc.AddMember("msg_type", net::api::MSG_ACCOUNT, allocator);
            doc.AddMember("msg_cmd", net::api::ACCOUNT_IMPORT, allocator);
            doc.AddMember("msg_id", msg_id, allocator);
            doc.AddMember("block_id", m_cur_block->id(), allocator);
            doc.AddMember("block_hash", rapidjson::StringRef(m_cur_block->hash().c_str()), allocator);
            std::shared_ptr<Account> account;
            
            if(!get_account(pubkey, account))
            {
                doc.AddMember("err_code", net::api::ERR_PUBKEY_NOT_REGISTERED, allocator);
                ASKCOIN_RETURN;
            }
            
            rapidjson::Value topic_list(rapidjson::kArrayType);
            uint32 topic_num = m_topic_list.size();

            if(topic_num <= 20)
            {
                for(auto topic : m_topic_list)
                {
                    auto owner = topic->get_owner();
                    auto block = topic->m_block;
                    uint64 block_id = block->id();
                    rapidjson::Value obj(rapidjson::kObjectType);
                    obj.AddMember("topic_key", rapidjson::StringRef(topic->key().c_str()), allocator);
                    obj.AddMember("topic_data", rapidjson::StringRef(topic->m_data.c_str()), allocator);
                    obj.AddMember("topic_reward", topic->get_total(), allocator);
                    obj.AddMember("block_id", block_id, allocator);
                    obj.AddMember("utc", block->utc(), allocator);
                    obj.AddMember("id", owner->id(), allocator);
                    obj.AddMember("avatar", owner->avatar(), allocator);
                    obj.AddMember("name", rapidjson::StringRef(owner->name().c_str()), allocator);
                    topic_list.PushBack(obj, allocator);
                }
            }
            else
            {
                uint32 cnt = 0;
                std::set<uint32> v_set;
                
                while(cnt < 20)
                {
                    uint32 v = fly::base::random_between(0, topic_num - 1);

                    if(v_set.find(v) != v_set.end())
                    {
                        continue;
                    }

                    v_set.insert(v);
                    ++cnt;
                }
                
                for(auto v : v_set)
                {
                    auto iter = m_topic_list.begin();
                    std::advance(iter, v);
                    auto topic = *iter;
                    auto owner = topic->get_owner();
                    auto block = topic->m_block;
                    uint64 block_id = block->id();
                    rapidjson::Value obj(rapidjson::kObjectType);
                    obj.AddMember("topic_key", rapidjson::StringRef(topic->key().c_str()), allocator);
                    obj.AddMember("topic_data", rapidjson::StringRef(topic->m_data.c_str()), allocator);
                    obj.AddMember("topic_reward", topic->get_total(), allocator);
                    obj.AddMember("block_id", block_id, allocator);
                    obj.AddMember("utc", block->utc(), allocator);
                    obj.AddMember("id", owner->id(), allocator);
                    obj.AddMember("avatar", owner->avatar(), allocator);
                    obj.AddMember("name", rapidjson::StringRef(owner->name().c_str()), allocator);
                    topic_list.PushBack(obj, allocator);
                }
            }
            
            doc.AddMember("topics", topic_list, allocator);
            rapidjson::Value question_list(rapidjson::kArrayType);
            rapidjson::Value answer_list(rapidjson::kArrayType);

            for(auto topic : account->m_topic_list)
            {
                auto owner = topic->get_owner();
                auto &block_hash = topic->m_block->hash();
                auto block = topic->m_block;
                uint64 block_id = block->id();
                rapidjson::Value obj(rapidjson::kObjectType);
                obj.AddMember("topic_key", rapidjson::StringRef(topic->key().c_str()), allocator);
                obj.AddMember("topic_data", rapidjson::StringRef(topic->m_data.c_str()), allocator);
                obj.AddMember("topic_reward", topic->get_total(), allocator);
                obj.AddMember("block_id", block_id, allocator);
                obj.AddMember("block_hash", rapidjson::StringRef(block_hash.c_str()), allocator);
                obj.AddMember("utc", block->utc(), allocator);
                obj.AddMember("id", owner->id(), allocator);
                obj.AddMember("avatar", owner->avatar(), allocator);
                obj.AddMember("name", rapidjson::StringRef(owner->name().c_str()), allocator);
                question_list.PushBack(obj, allocator);
            }
            
            for(auto topic : account->m_joined_topic_list)
            {
                auto owner = topic->get_owner();
                auto block = topic->m_block;
                uint64 block_id = block->id();
                rapidjson::Value obj(rapidjson::kObjectType);
                obj.AddMember("topic_key", rapidjson::StringRef(topic->key().c_str()), allocator);
                obj.AddMember("topic_data", rapidjson::StringRef(topic->m_data.c_str()), allocator);
                obj.AddMember("topic_reward", topic->get_total(), allocator);
                obj.AddMember("block_id", block_id, allocator);
                obj.AddMember("utc", block->utc(), allocator);
                obj.AddMember("id", owner->id(), allocator);
                obj.AddMember("avatar", owner->avatar(), allocator);
                obj.AddMember("name", rapidjson::StringRef(owner->name().c_str()), allocator);
                answer_list.PushBack(obj, allocator);
            }
            
            doc.AddMember("questions", question_list, allocator);
            doc.AddMember("answers", answer_list, allocator);
            connection->send(doc);
            user->m_state = 2;
            lock.lock();
            wsock_node->m_users_by_pubkey.insert(std::make_pair(pubkey, user));
            user->m_pubkey = pubkey;
        }
        else
        {
            connection->close();
            ASKCOIN_RETURN;
        }
        
        return;
    }
    else if(type == net::api::MSG_TOPIC)
    {
        if(user->m_state != 2)
        {
            connection->close();
            ASKCOIN_RETURN;
        }
        
        std::shared_ptr<Account> account;
        
        if(!get_account(user->m_pubkey, account))
        {
            connection->close();
            ASKCOIN_RETURN;
        }
        
        if(cmd == net::api::TOPIC_QUESTION_PROBE)
        {
            if(!doc.HasMember("type"))
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(!doc["type"].IsUint())
            {
                connection->close();
                ASKCOIN_RETURN;
            }
            
            uint32 type = doc["type"].GetUint();
            rapidjson::Document doc;
            doc.SetObject();
            rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
            doc.AddMember("msg_type", net::api::MSG_TOPIC, allocator);
            doc.AddMember("msg_cmd", net::api::TOPIC_QUESTION_PROBE, allocator);
            doc.AddMember("msg_id", msg_id, allocator);

            if(type == 0)
            {
                doc.AddMember("result", 0, allocator);
                rapidjson::Value question_list(rapidjson::kArrayType);
                
                for(auto topic : account->m_topic_list)
                {
                    auto owner = topic->get_owner();
                    auto block = topic->m_block;
                    auto &block_hash = block->hash();
                    uint64 block_id = block->id();
                    rapidjson::Value obj(rapidjson::kObjectType);
                    obj.AddMember("topic_key", rapidjson::StringRef(topic->key().c_str()), allocator);
                    obj.AddMember("topic_data", rapidjson::StringRef(topic->m_data.c_str()), allocator);
                    obj.AddMember("topic_reward", topic->get_total(), allocator);
                    obj.AddMember("block_id", block_id, allocator);
                    obj.AddMember("block_hash", rapidjson::StringRef(block_hash.c_str()), allocator);
                    obj.AddMember("utc", block->utc(), allocator);
                    obj.AddMember("id", owner->id(), allocator);
                    obj.AddMember("avatar", owner->avatar(), allocator);
                    obj.AddMember("name", rapidjson::StringRef(owner->name().c_str()), allocator);
                    question_list.PushBack(obj, allocator);
                }
                
                doc.AddMember("questions", question_list, allocator);
                connection->send(doc);
            }
            else if(type == 1)
            {
                if(!doc.HasMember("topic_key"))
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }
                
                if(!doc["topic_key"].IsString())
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }
                
                std::string topic_key = doc["topic_key"].GetString();
            
                if(!is_base64_char(topic_key))
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }
                
                if(topic_key.length() != 44)
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }
                
                if(!doc.HasMember("block_hash"))
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }
                
                if(!doc["block_hash"].IsString())
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }
                
                std::string block_hash = doc["block_hash"].GetString();
            
                if(block_hash.length() != 44)
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }
                
                if(!is_base64_char(block_hash))
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }

                auto iter = m_blocks.find(block_hash);

                if(iter == m_blocks.end())
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }
                
                auto block = m_blocks[block_hash];
                doc.AddMember("topic_key", rapidjson::StringRef(topic_key.c_str()), allocator);

                if(account->m_topic_list.empty())
                {
                    doc.AddMember("result", 0, allocator);
                    rapidjson::Value question_list(rapidjson::kArrayType);
                    doc.AddMember("questions", question_list, allocator);
                    connection->send(doc);
                    ASKCOIN_RETURN;
                }
                
                auto topic_begin = *account->m_topic_list.begin();
                
                if(block->id() < topic_begin->m_block->id())
                {
                    doc.AddMember("result", 0, allocator);
                    rapidjson::Value question_list(rapidjson::kArrayType);
                
                    for(auto topic : account->m_topic_list)
                    {
                        auto owner = topic->get_owner();
                        auto block = topic->m_block;
                        auto &block_hash = block->hash();
                        uint64 block_id = block->id();
                        rapidjson::Value obj(rapidjson::kObjectType);
                        obj.AddMember("topic_key", rapidjson::StringRef(topic->key().c_str()), allocator);
                        obj.AddMember("topic_data", rapidjson::StringRef(topic->m_data.c_str()), allocator);
                        obj.AddMember("topic_reward", topic->get_total(), allocator);
                        obj.AddMember("block_id", block_id, allocator);
                        obj.AddMember("block_hash", rapidjson::StringRef(block_hash.c_str()), allocator);
                        obj.AddMember("utc", block->utc(), allocator);
                        obj.AddMember("id", owner->id(), allocator);
                        obj.AddMember("avatar", owner->avatar(), allocator);
                        obj.AddMember("name", rapidjson::StringRef(owner->name().c_str()), allocator);
                        question_list.PushBack(obj, allocator);
                    }
                
                    doc.AddMember("questions", question_list, allocator);
                    connection->send(doc);
                    ASKCOIN_RETURN;
                }

                uint32 cnt = 0;

                for(auto iter = account->m_topic_list.rbegin(); iter != account->m_topic_list.rend(); ++iter)
                {
                    auto topic = *iter;
                    
                    if(block->id() > topic->m_block->id())
                    {
                        doc.AddMember("result", 2, allocator);
                        connection->send(doc);
                        return;
                    }

                    if(topic->key() == topic_key)
                    {
                        if(block_hash == topic->m_block->hash())
                        {
                            uint32 v = account->m_topic_list.size() - cnt;
                            auto iter = account->m_topic_list.begin();
                            std::advance(iter, v);
                            doc.AddMember("result", 1, allocator);
                            rapidjson::Value question_list(rapidjson::kArrayType);
                                
                            for(; iter != account->m_topic_list.end(); ++iter)
                            {
                                auto topic = *iter;
                                auto owner = topic->get_owner();
                                auto block = topic->m_block;
                                auto &block_hash = block->hash();
                                uint64 block_id = block->id();
                                rapidjson::Value obj(rapidjson::kObjectType);
                                obj.AddMember("topic_key", rapidjson::StringRef(topic->key().c_str()), allocator);
                                obj.AddMember("topic_data", rapidjson::StringRef(topic->m_data.c_str()), allocator);
                                obj.AddMember("topic_reward", topic->get_total(), allocator);
                                obj.AddMember("block_id", block_id, allocator);
                                obj.AddMember("block_hash", rapidjson::StringRef(block_hash.c_str()), allocator);
                                obj.AddMember("utc", block->utc(), allocator);
                                obj.AddMember("id", owner->id(), allocator);
                                obj.AddMember("avatar", owner->avatar(), allocator);
                                obj.AddMember("name", rapidjson::StringRef(owner->name().c_str()), allocator);
                                question_list.PushBack(obj, allocator);
                            }
                            
                            doc.AddMember("questions", question_list, allocator);
                            connection->send(doc);
                            return;
                        }
                        
                        break;
                    }

                    ++cnt;
                }
                
                doc.AddMember("result", 2, allocator);
                connection->send(doc);
            }
            else
            {
                connection->close();
                ASKCOIN_RETURN;
            }
        }
        else if(cmd == net::api::TOPIC_DETAIL_PROBE)
        {
            if(!doc.HasMember("topic_key"))
            {
                connection->close();
                ASKCOIN_RETURN;
            }
            
            if(!doc["topic_key"].IsString())
            {
                connection->close();
                ASKCOIN_RETURN;
            }
            
            std::string topic_key = doc["topic_key"].GetString();
            
            if(!is_base64_char(topic_key))
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(topic_key.length() != 44)
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(!doc.HasMember("type"))
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(!doc["type"].IsUint())
            {
                connection->close();
                ASKCOIN_RETURN;
            }
            
            uint32 type = doc["type"].GetUint();
            rapidjson::Document doc;
            doc.SetObject();
            rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
            doc.AddMember("msg_type", net::api::MSG_TOPIC, allocator);
            doc.AddMember("msg_cmd", net::api::TOPIC_DETAIL_PROBE, allocator);
            doc.AddMember("msg_id", msg_id, allocator);
            doc.AddMember("topic_key", rapidjson::StringRef(topic_key.c_str()), allocator);
            std::shared_ptr<Topic> topic;
            
            if(!get_topic(topic_key, topic))
            {
                doc.AddMember("result", 3, allocator);
                connection->send(doc);
                ASKCOIN_RETURN;
            }
            
            doc.AddMember("topic_balance", topic->get_balance(), allocator);

            if(type == 0)
            {
                doc.AddMember("result", 0, allocator);
                rapidjson::Value reply_list(rapidjson::kArrayType);
                
                for(auto reply : topic->m_reply_list)
                {
                    auto owner = reply->get_owner();
                    auto block = reply->m_block;
                    auto &block_hash = block->hash();
                    uint64 block_id = block->id();
                    rapidjson::Value obj(rapidjson::kObjectType);
                    obj.AddMember("reply_key", rapidjson::StringRef(reply->key().c_str()), allocator);
                    obj.AddMember("type", reply->type(), allocator);
                    obj.AddMember("reply_data", rapidjson::StringRef(reply->m_data.c_str()), allocator);
                    obj.AddMember("balance", reply->get_balance(), allocator);
                    obj.AddMember("block_id", block_id, allocator);
                    obj.AddMember("block_hash", rapidjson::StringRef(block_hash.c_str()), allocator);
                    obj.AddMember("utc", block->utc(), allocator);
                    obj.AddMember("id", owner->id(), allocator);
                    obj.AddMember("avatar", owner->avatar(), allocator);
                    obj.AddMember("name", rapidjson::StringRef(owner->name().c_str()), allocator);
                    std::shared_ptr<Reply> reply_to = reply->get_reply_to();
                    
                    if(reply_to)
                    {
                        obj.AddMember("reply_to", rapidjson::StringRef(reply_to->key().c_str()), allocator);
                    }

                    reply_list.PushBack(obj, allocator);
                }
                
                doc.AddMember("replies", reply_list, allocator);
                connection->send(doc);
            }
            else if(type == 1)
            {
                if(!doc.HasMember("block_hash"))
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }
                
                if(!doc["block_hash"].IsString())
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }
            
                std::string block_hash = doc["block_hash"].GetString();
            
                if(block_hash.length() != 44)
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }
                
                if(!is_base64_char(block_hash))
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }
                
                if(!doc.HasMember("reply_key"))
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }
                
                if(!doc["reply_key"].IsString())
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }
            
                std::string reply_key = doc["reply_key"].GetString();
            
                if(reply_key.length() != 44)
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }
                
                if(!is_base64_char(reply_key))
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }

                doc.AddMember("reply_key", rapidjson::StringRef(reply_key.c_str()), allocator);
                
                if(topic->m_reply_list.empty())
                {
                    doc.AddMember("result", 0, allocator);
                    rapidjson::Value reply_list(rapidjson::kArrayType);
                    doc.AddMember("replies", reply_list, allocator);
                    connection->send(doc);
                    ASKCOIN_RETURN;
                }
                
                auto iter = m_blocks.find(block_hash);
                
                if(iter == m_blocks.end())
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }

                
                auto block = m_blocks[block_hash];
                auto reply_begin = *topic->m_reply_list.begin();
                
                if(block->id() < reply_begin->m_block->id())
                {
                    doc.AddMember("result", 0, allocator);
                    rapidjson::Value reply_list(rapidjson::kArrayType);
                
                    for(auto reply : topic->m_reply_list)
                    {
                        auto owner = reply->get_owner();
                        auto block = reply->m_block;
                        auto &block_hash = block->hash();
                        uint64 block_id = block->id();
                        rapidjson::Value obj(rapidjson::kObjectType);
                        obj.AddMember("reply_key", rapidjson::StringRef(reply->key().c_str()), allocator);
                        obj.AddMember("type", reply->type(), allocator);
                        obj.AddMember("reply_data", rapidjson::StringRef(reply->m_data.c_str()), allocator);
                        obj.AddMember("balance", reply->get_balance(), allocator);
                        obj.AddMember("block_id", block_id, allocator);
                        obj.AddMember("block_hash", rapidjson::StringRef(block_hash.c_str()), allocator);
                        obj.AddMember("utc", block->utc(), allocator);
                        obj.AddMember("id", owner->id(), allocator);
                        obj.AddMember("avatar", owner->avatar(), allocator);
                        obj.AddMember("name", rapidjson::StringRef(owner->name().c_str()), allocator);
                        std::shared_ptr<Reply> reply_to = reply->get_reply_to();
                    
                        if(reply_to)
                        {
                            obj.AddMember("reply_to", rapidjson::StringRef(reply_to->key().c_str()), allocator);
                        }

                        reply_list.PushBack(obj, allocator);
                    }
                
                    doc.AddMember("replies", reply_list, allocator);
                    connection->send(doc);
                    ASKCOIN_RETURN;
                }
                
                uint32 cnt = 0;
                
                for(auto iter = topic->m_reply_list.rbegin(); iter != topic->m_reply_list.rend(); ++iter)
                {
                    auto reply = *iter;
                    
                    if(block->id() > reply->m_block->id())
                    {
                        doc.AddMember("result", 2, allocator);
                        connection->send(doc);
                        return;
                    }
                    
                    if(reply->key() == reply_key)
                    {
                        if(block_hash == reply->m_block->hash())
                        {
                            uint32 v = topic->m_reply_list.size() - cnt;
                            auto iter = topic->m_reply_list.begin();
                            std::advance(iter, v);
                            doc.AddMember("result", 1, allocator);
                            rapidjson::Value reply_list(rapidjson::kArrayType);
                            
                            for(; iter != topic->m_reply_list.end(); ++iter)
                            {
                                auto owner = reply->get_owner();
                                auto block = reply->m_block;
                                auto &block_hash = block->hash();
                                uint64 block_id = block->id();
                                rapidjson::Value obj(rapidjson::kObjectType);
                                obj.AddMember("reply_key", rapidjson::StringRef(reply->key().c_str()), allocator);
                                obj.AddMember("type", reply->type(), allocator);
                                obj.AddMember("reply_data", rapidjson::StringRef(reply->m_data.c_str()), allocator);
                                obj.AddMember("balance", reply->get_balance(), allocator);
                                obj.AddMember("block_id", block_id, allocator);
                                obj.AddMember("block_hash", rapidjson::StringRef(block_hash.c_str()), allocator);
                                obj.AddMember("utc", block->utc(), allocator);
                                obj.AddMember("id", owner->id(), allocator);
                                obj.AddMember("avatar", owner->avatar(), allocator);
                                obj.AddMember("name", rapidjson::StringRef(owner->name().c_str()), allocator);
                                std::shared_ptr<Reply> reply_to = reply->get_reply_to();
                    
                                if(reply_to)
                                {
                                    obj.AddMember("reply_to", rapidjson::StringRef(reply_to->key().c_str()), allocator);
                                }

                                reply_list.PushBack(obj, allocator);
                            }
                            
                            doc.AddMember("replies", reply_list, allocator);
                            connection->send(doc);
                            return;
                        }
                        
                        break;
                    }

                    ++cnt;
                }
                
                doc.AddMember("result", 2, allocator);
                connection->send(doc);
            }
            else
            {
                connection->close();
                ASKCOIN_RETURN;
            }
        }
        else if(cmd == net::api::TOPIC_ANSWER_LIST)
        {
            rapidjson::Document doc;
            doc.SetObject();
            rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
            doc.AddMember("msg_type", net::api::MSG_TOPIC, allocator);
            doc.AddMember("msg_cmd", net::api::TOPIC_ANSWER_LIST, allocator);
            doc.AddMember("msg_id", msg_id, allocator);
            rapidjson::Value answer_list(rapidjson::kArrayType);
            
            for(auto topic : account->m_joined_topic_list)
            {
                auto owner = topic->get_owner();
                auto block = topic->m_block;
                uint64 block_id = block->id();
                rapidjson::Value obj(rapidjson::kObjectType);
                obj.AddMember("topic_key", rapidjson::StringRef(topic->key().c_str()), allocator);
                obj.AddMember("topic_data", rapidjson::StringRef(topic->m_data.c_str()), allocator);
                obj.AddMember("topic_reward", topic->get_total(), allocator);
                obj.AddMember("block_id", block_id, allocator);
                obj.AddMember("utc", block->utc(), allocator);
                obj.AddMember("id", owner->id(), allocator);
                obj.AddMember("avatar", owner->avatar(), allocator);
                obj.AddMember("name", rapidjson::StringRef(owner->name().c_str()), allocator);
                answer_list.PushBack(obj, allocator);
            }

            doc.AddMember("answers", answer_list, allocator);
            connection->send(doc);
        }
        else
        {
            connection->close();
            ASKCOIN_RETURN;
        }
        
        return;
    }
    
    if(type != net::api::MSG_TX || cmd != net::api::TX_CMD)
    {
        connection->close();
        ASKCOIN_RETURN;
    }
    
    if(!doc.HasMember("sign"))
    {
        connection->close();
        ASKCOIN_RETURN;
    }
    
    if(!doc["sign"].IsString())
    {
        connection->close();
        ASKCOIN_RETURN;
    }
    
    if(!doc.HasMember("data"))
    {
        connection->close();
        ASKCOIN_RETURN;
    }
    
    std::string tx_sign = doc["sign"].GetString();
    
    if(!is_base64_char(tx_sign))
    {
        connection->close();
        ASKCOIN_RETURN;
    }

    rapidjson::Value &doc_data = doc["data"];
            
    if(!doc_data.IsObject())
    {
        connection->close();
        ASKCOIN_RETURN;
    }
    
    if(!doc_data.HasMember("type"))
    {
        connection->close();
        ASKCOIN_RETURN;
    }
            
    if(!doc_data.HasMember("pubkey"))
    {
        connection->close();
        ASKCOIN_RETURN;
    }
            
    if(!doc_data.HasMember("utc"))
    {
        connection->close();
        ASKCOIN_RETURN;
    }

    if(!doc_data["pubkey"].IsString())
    {
        connection->close();
        ASKCOIN_RETURN;
    }
    
    std::string pubkey = doc_data["pubkey"].GetString();
                
    if(!is_base64_char(pubkey))
    {
        connection->close();
        ASKCOIN_RETURN;
    }

    if(pubkey.length() != 88)
    {
        connection->close();
        ASKCOIN_RETURN;
    }

    if(!doc_data["type"].IsUint())
    {
        connection->close();
        ASKCOIN_RETURN;
    }

    if(!doc_data["utc"].IsUint64())
    {
        connection->close();
        ASKCOIN_RETURN;
    }

    uint32 tx_type = doc_data["type"].GetUint();
    uint64 utc = doc_data["utc"].GetUint64();
    rapidjson::Document rsp_doc;
    rsp_doc.SetObject();
    rapidjson::Document::AllocatorType &allocator = rsp_doc.GetAllocator();
    rsp_doc.AddMember("msg_type", type, allocator);
    rsp_doc.AddMember("msg_cmd", cmd, allocator);
    rsp_doc.AddMember("msg_id", msg_id, allocator);
    rsp_doc.AddMember("type", tx_type, allocator);
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    doc_data.Accept(writer);
    std::string tx_id = coin_hash_b64(buffer.GetString(), buffer.GetSize());

    if(!verify_sign(pubkey, tx_id, tx_sign))
    {
        connection->close();
        ASKCOIN_RETURN;
    }

    if(m_tx_map.find(tx_id) != m_tx_map.end())
    {
        rsp_doc.AddMember("err_code", net::api::ERR_TX_EXIST, allocator);
        connection->send(rsp_doc);
        ASKCOIN_RETURN;
    }
    
    if(m_uv_tx_ids.find(tx_id) != m_uv_tx_ids.end())
    {
        rsp_doc.AddMember("err_code", net::api::ERR_TX_EXIST, allocator);
        connection->send(rsp_doc);
        ASKCOIN_RETURN;
    }

    uint64 cur_block_id  = m_cur_block->id();
    auto doc_ptr = std::make_shared<rapidjson::Document>();
    auto &p2p_doc = *doc_ptr;
    p2p_doc.SetObject();
    rapidjson::Document::AllocatorType &p2p_allocator = p2p_doc.GetAllocator();
    p2p_doc.AddMember("msg_type", net::p2p::MSG_TX, p2p_allocator);
    p2p_doc.AddMember("msg_cmd", net::p2p::TX_BROADCAST, p2p_allocator);
    p2p_doc.AddMember("sign", rapidjson::Value().CopyFrom(doc["sign"], p2p_allocator), p2p_allocator);
    p2p_doc.AddMember("data", rapidjson::Value().CopyFrom(doc_data, p2p_allocator), p2p_allocator);
    auto &data = p2p_doc["data"];
    
    if(tx_type == 1)
    {
        if(user->m_state != 0)
        {
            connection->close();
            ASKCOIN_RETURN;
        }
        
        if(!data.HasMember("avatar"))
        {
            connection->close();
            ASKCOIN_RETURN;
        }
        
        if(!data["avatar"].IsUint())
        {
            connection->close();
            ASKCOIN_RETURN;
        }
        
        if(!data.HasMember("sign"))
        {
            connection->close();
            ASKCOIN_RETURN;
        }
        
        if(!data["sign"].IsString())
        {
            connection->close();
            ASKCOIN_RETURN;
        }
                    
        std::shared_ptr<Account> exist_account;
                
        if(get_account(pubkey, exist_account))
        {
            rsp_doc.AddMember("err_code", net::api::ERR_PUBKEY_EXIST, allocator);
            connection->send(rsp_doc);
            ASKCOIN_RETURN;
        }

        if(m_uv_account_pubkeys.find(pubkey) != m_uv_account_pubkeys.end())
        {
            rsp_doc.AddMember("err_code", net::api::ERR_PUBKEY_EXIST, allocator);
            connection->send(rsp_doc);
            ASKCOIN_RETURN;
        }
        
        if(!data.HasMember("sign_data"))
        {
            connection->close();
            ASKCOIN_RETURN;
        }

        std::string reg_sign = data["sign"].GetString();

        if(!is_base64_char(reg_sign))
        {
            connection->close();
            ASKCOIN_RETURN;
        }
                
        const rapidjson::Value &sign_data = data["sign_data"];

        if(!sign_data.IsObject())
        {
            connection->close();
            ASKCOIN_RETURN;
        }
                    
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        sign_data.Accept(writer);
        std::string sign_hash = coin_hash_b64(buffer.GetString(), buffer.GetSize());
                
        if(!sign_data.HasMember("block_id"))
        {
            connection->close();
            ASKCOIN_RETURN;
        }

        if(!sign_data["block_id"].IsUint64())
        {
            connection->close();
            ASKCOIN_RETURN;
        }
                    
        if(!sign_data.HasMember("name"))
        {
            connection->close();
            ASKCOIN_RETURN;
        }

        if(!sign_data["name"].IsString())
        {
            connection->close();
            ASKCOIN_RETURN;
        }
                    
        if(!sign_data.HasMember("referrer"))
        {
            connection->close();
            ASKCOIN_RETURN;
        }

        if(!sign_data["referrer"].IsString())
        {
            connection->close();
            ASKCOIN_RETURN;
        }
                    
        if(!sign_data.HasMember("fee"))
        {
            connection->close();
            ASKCOIN_RETURN;
        }

        if(!sign_data["fee"].IsUint64())
        {
            connection->close();
            ASKCOIN_RETURN;
        }
                    
        uint64 block_id = sign_data["block_id"].GetUint64();
        std::string register_name = sign_data["name"].GetString();
        std::string referrer_pubkey = sign_data["referrer"].GetString();
        uint64 fee = sign_data["fee"].GetUint64();

        if(block_id == 0)
        {
            connection->close();
            ASKCOIN_RETURN;
        }

        if(block_id + 100 < cur_block_id + 1 || block_id > cur_block_id + 1 + 100)
        {
            rsp_doc.AddMember("err_code", net::api::ERR_SIGN_EXPIRED, allocator);
            connection->send(rsp_doc);
            ASKCOIN_RETURN;
        }
        
        if(fee != 2)
        {
            connection->close();
            ASKCOIN_RETURN;
        }
                
        if(!is_base64_char(referrer_pubkey))
        {
            connection->close();
            ASKCOIN_RETURN;
        }

        if(referrer_pubkey.length() != 88)
        {
            connection->close();
            ASKCOIN_RETURN;
        }
                
        if(!verify_sign(referrer_pubkey, sign_hash, reg_sign))
        {
            connection->close();
            ASKCOIN_RETURN;
        }

        if(!is_base64_char(register_name))
        {
            connection->close();
            ASKCOIN_RETURN;
        }

        if(register_name.length() > 20 || register_name.length() < 4)
        {
            connection->close();
            ASKCOIN_RETURN;
        }
                    
        if(account_name_exist(register_name))
        {
            rsp_doc.AddMember("err_code", net::api::ERR_NAME_EXIST, allocator);
            connection->send(rsp_doc);
            ASKCOIN_RETURN;
        }
        
        if(m_uv_account_names.find(register_name) != m_uv_account_names.end())
        {
            rsp_doc.AddMember("err_code", net::api::ERR_NAME_EXIST, allocator);
            connection->send(rsp_doc);
            ASKCOIN_RETURN;
        }
        
        char raw_name[15] = {0};
        uint32 len = fly::base::base64_decode(register_name.c_str(), register_name.length(), raw_name, 15);
                
        if(len > 15 || len == 0)
        {
            connection->close();
            ASKCOIN_RETURN;
        }
                    
        for(uint32 i = 0; i < len; ++i)
        {
            if(std::isspace(static_cast<unsigned char>(raw_name[i])))
            {
                connection->close();
                ASKCOIN_RETURN;
            }
        }
        
        uint32 avatar = data["avatar"].GetUint();

        if(avatar < 1 || avatar > 100)
        {
            connection->close();
            ASKCOIN_RETURN;
        }
        
        std::shared_ptr<Account> referrer;

        if(!get_account(referrer_pubkey, referrer))
        {
            rsp_doc.AddMember("err_code", net::api::ERR_REFERRER_NOT_EXIST, allocator);
            connection->send(rsp_doc);
            ASKCOIN_RETURN;
        }
                
        if(referrer->get_balance() < 2 + referrer->m_uv_spend)
        {
            rsp_doc.AddMember("err_code", net::api::ERR_REFERRER_BALANCE_NOT_ENOUGH, allocator);
            connection->send(rsp_doc);
            ASKCOIN_RETURN;
        }

        std::shared_ptr<tx::Tx_Reg> tx_reg(new tx::Tx_Reg);
        tx_reg->m_id = tx_id;
        tx_reg->m_type = 1;
        tx_reg->m_utc = utc;
        tx_reg->m_doc = doc_ptr;
        tx_reg->m_pubkey = pubkey;
        tx_reg->m_block_id = block_id;
        tx_reg->m_register_name = register_name;
        tx_reg->m_avatar = avatar;
        tx_reg->m_referrer_pubkey = referrer_pubkey;
        m_uv_tx_ids.insert(tx_id);
        m_uv_account_names.insert(register_name);
        m_uv_account_pubkeys.insert(pubkey);
        m_uv_2_txs.push_back(tx_reg);
        referrer->m_uv_spend += 2;
        net::p2p::Node::instance()->broadcast(p2p_doc);
        connection->send(rsp_doc);
        user->m_state = 1;
        user->m_pubkey = pubkey;
        lock.lock();
        wsock_node->m_users_to_register.insert(std::make_pair(pubkey, user));
    }
    else
    {
        if(user->m_state != 2)
        {
            connection->close();
            ASKCOIN_RETURN;
        }
        
        if(!data.HasMember("fee"))
        {
            connection->close();
            ASKCOIN_RETURN;
        }
        
        if(!data["fee"].IsUint64())
        {
            connection->close();
            ASKCOIN_RETURN;
        }
        
        if(!data.HasMember("block_id"))
        {
            connection->close();
            ASKCOIN_RETURN;
        }

        if(!data["block_id"].IsUint64())
        {
            connection->close();
            ASKCOIN_RETURN;
        }
                    
        uint64 fee = data["fee"].GetUint64();
        uint64 block_id = data["block_id"].GetUint64();
                    
        if(block_id == 0)
        {
            connection->close();
            ASKCOIN_RETURN;
        }
        
        if(block_id + 100 < cur_block_id + 1 || block_id > cur_block_id + 1 + 100)
        {
            rsp_doc.AddMember("err_code", net::api::ERR_TX_EXPIRED, allocator);
            connection->send(rsp_doc);
            ASKCOIN_RETURN;
        }
        
        if(fee != 2)
        {
            connection->close();
            ASKCOIN_RETURN;
        }
        
        std::shared_ptr<Account> account;
        
        if(!get_account(pubkey, account))
        {
            rsp_doc.AddMember("err_code", net::api::ERR_PUBKEY_NOT_REGISTERED, allocator);
            connection->send(rsp_doc);
            ASKCOIN_RETURN;
        }
        
        if(tx_type == 2) // send coin
        {
            if(data.HasMember("memo"))
            {
                if(!data["memo"].IsString())
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }

                std::string memo = data["memo"].GetString();

                if(memo.empty())
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }
                
                if(!is_base64_char(memo))
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }
                
                if(memo.length() > 80 || memo.length() < 4)
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }
            }
            
            if(!data.HasMember("amount"))
            {
                connection->close();
                ASKCOIN_RETURN;
            }
                        
            if(!data["amount"].IsUint64())
            {
                connection->close();
                ASKCOIN_RETURN;
            }
                        
            uint64 amount = data["amount"].GetUint64();
                        
            if(amount == 0)
            {
                connection->close();
                ASKCOIN_RETURN;
            }
            
            if(!data.HasMember("receiver"))
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(!data["receiver"].IsString())
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            std::string receiver_pubkey = data["receiver"].GetString();
                        
            if(!is_base64_char(receiver_pubkey))
            {
                connection->close();
                ASKCOIN_RETURN;
            }
            
            if(receiver_pubkey.length() != 88)
            {
                connection->close();
                ASKCOIN_RETURN;
            }
            
            if(account->get_balance() < amount + 2 + account->m_uv_spend)
            {
                rsp_doc.AddMember("err_code", net::api::ERR_BALANCE_NOT_ENOUGH, allocator);
                connection->send(rsp_doc);
                ASKCOIN_RETURN;
            }
            
            std::shared_ptr<Account> receiver;
            
            if(!get_account(receiver_pubkey, receiver))
            {
                rsp_doc.AddMember("err_code", net::api::ERR_RECEIVER_NOT_EXIST, allocator);
                connection->send(rsp_doc);
                ASKCOIN_RETURN;
            }
            
            std::shared_ptr<tx::Tx_Send> tx_send(new tx::Tx_Send);
            tx_send->m_id = tx_id;
            tx_send->m_type = 2;
            tx_send->m_utc = utc;
            tx_send->m_doc = doc_ptr;
            tx_send->m_pubkey = pubkey;
            tx_send->m_block_id = block_id;
            tx_send->m_receiver_pubkey = receiver_pubkey;
            tx_send->m_amount = amount;
            m_uv_tx_ids.insert(tx_id);
            m_uv_2_txs.push_back(tx_send);
            account->m_uv_spend += amount + 2;
            net::p2p::Node::instance()->broadcast(p2p_doc);
            connection->send(rsp_doc);
        }
        else if(tx_type == 3)
        {
            if(!data.HasMember("reward"))
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(!data["reward"].IsUint64())
            {
                connection->close();
                ASKCOIN_RETURN;
            }
                        
            uint64 reward = data["reward"].GetUint64();

            if(reward == 0)
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            std::shared_ptr<Topic> exist_topic;

            if(get_topic(tx_id, exist_topic))
            {
                rsp_doc.AddMember("err_code", net::api::ERR_TOPIC_EXIST, allocator);
                connection->send(rsp_doc);
                ASKCOIN_RETURN;
            }
            
            if(!data.HasMember("topic"))
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(!data["topic"].IsString())
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            std::string topic_data = data["topic"].GetString();
                    
            if(!is_base64_char(topic_data))
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(topic_data.length() < 4 || topic_data.length() > 400)
            {
                connection->close();
                ASKCOIN_RETURN;
            }
            
            if(account->m_topic_list.size() + account->m_uv_topic >= 100)
            {
                rsp_doc.AddMember("err_code", net::api::ERR_TOPIC_NUM_EXCEED_LIMIT, allocator);
                connection->send(rsp_doc);
                ASKCOIN_RETURN;
            }
                    
            if(account->get_balance() < reward + 2 + account->m_uv_spend)
            {
                rsp_doc.AddMember("err_code", net::api::ERR_BALANCE_NOT_ENOUGH, allocator);
                connection->send(rsp_doc);
                ASKCOIN_RETURN;
            }
            
            std::shared_ptr<tx::Tx_Topic> tx_topic(new tx::Tx_Topic);
            tx_topic->m_id = tx_id;
            tx_topic->m_type = 3;
            tx_topic->m_utc = utc;
            tx_topic->m_doc = doc_ptr;
            tx_topic->m_pubkey = pubkey;
            tx_topic->m_block_id = block_id;
            tx_topic->m_reward = reward;
            m_uv_tx_ids.insert(tx_id);
            m_uv_2_txs.push_back(tx_topic);
            account->m_uv_spend += reward + 2;
            account->m_uv_topic += 1;
            net::p2p::Node::instance()->broadcast(p2p_doc);
            connection->send(rsp_doc);
        }
        else if(tx_type == 4)
        {
            if(!data.HasMember("topic_key"))
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(!data["topic_key"].IsString())
            {
                connection->close();
                ASKCOIN_RETURN;
            }
                        
            std::string topic_key = data["topic_key"].GetString();
                        
            if(!is_base64_char(topic_key))
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(topic_key.length() != 44)
            {
                connection->close();
                ASKCOIN_RETURN;
            }
                    
            if(!data.HasMember("reply"))
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(!data["reply"].IsString())
            {
                connection->close();
                ASKCOIN_RETURN;
            }
                        
            std::string reply_data = data["reply"].GetString();
                    
            if(!is_base64_char(reply_data))
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(reply_data.length() < 4 || reply_data.length() > 400)
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            std::shared_ptr<Topic> topic;

            if(!get_topic(topic_key, topic))
            {
                rsp_doc.AddMember("err_code", net::api::ERR_TOPIC_NOT_EXIST, allocator);
                connection->send(rsp_doc);
                ASKCOIN_RETURN;
            }

            uint64 topic_block_id = topic->m_block->id();
            
            if(topic_block_id + TOPIC_LIFE_TIME < cur_block_id + 1)
            {
                rsp_doc.AddMember("err_code", net::api::ERR_TOPIC_NOT_EXIST, allocator);
                connection->send(rsp_doc);
                ASKCOIN_RETURN;
            }
            
            std::shared_ptr<tx::Tx_Reply> tx_reply(new tx::Tx_Reply);
            
            if(data.HasMember("reply_to"))
            {
                if(!data["reply_to"].IsString())
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }
                        
                std::string reply_to_key = data["reply_to"].GetString();
                            
                if(!is_base64_char(reply_to_key))
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }

                if(reply_to_key.length() != 44)
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }

                tx_reply->m_reply_to = reply_to_key;
                std::shared_ptr<Reply> reply_to;

                if(!topic->get_reply(reply_to_key, reply_to))
                {
                    rsp_doc.AddMember("err_code", net::api::ERR_REPLY_NOT_EXIST, allocator);
                    connection->send(rsp_doc);
                    ASKCOIN_RETURN;
                }
                
                if(reply_to->type() != 0)
                {
                    connection->close();
                    ASKCOIN_RETURN;
                }
            }
            
            if(topic->m_reply_list.size() + topic->m_uv_reply >= 1000)
            {
                rsp_doc.AddMember("err_code", net::api::ERR_REPLY_NUM_EXCEED_LIMIT, allocator);
                connection->send(rsp_doc);
                ASKCOIN_RETURN;
            }
            
            if(account->get_balance() < 2 + account->m_uv_spend)
            {
                rsp_doc.AddMember("err_code", net::api::ERR_BALANCE_NOT_ENOUGH, allocator);
                connection->send(rsp_doc);
                ASKCOIN_RETURN;
            }
            
            if(topic->get_owner() != account)
            {
                if(!account->joined_topic(topic))
                {
                    if(account->m_joined_topic_list.size() + account->m_uv_join_topic >= 100)
                    {
                        rsp_doc.AddMember("err_code", net::api::ERR_JOINED_TOPIC_NUM_EXCEED_LIMIT, allocator);
                        connection->send(rsp_doc);
                        ASKCOIN_RETURN;
                    }
                    
                    account->m_uv_join_topic += 1;
                    tx_reply->m_uv_join_topic = 1;
                }
            }
            
            tx_reply->m_id = tx_id;
            tx_reply->m_type = 4;
            tx_reply->m_utc = utc;
            tx_reply->m_doc = doc_ptr;
            tx_reply->m_pubkey = pubkey;
            tx_reply->m_block_id = block_id;
            tx_reply->m_topic_key = topic_key;
            m_uv_tx_ids.insert(tx_id);
            account->m_uv_spend += 2;
            topic->m_uv_reply += 1;
            m_uv_2_txs.push_back(tx_reply);
            net::p2p::Node::instance()->broadcast(p2p_doc);
            connection->send(rsp_doc);
        }
        else if(tx_type == 5)
        {
            if(!data.HasMember("topic_key"))
            {
                connection->close();
                ASKCOIN_RETURN;
            }
                    
            if(!data["topic_key"].IsString())
            {
                connection->close();
                ASKCOIN_RETURN;
            }
                        
            std::string topic_key = data["topic_key"].GetString();
                    
            if(!is_base64_char(topic_key))
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(topic_key.length() != 44)
            {
                connection->close();
                ASKCOIN_RETURN;
            }
                    
            if(!data.HasMember("amount"))
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(!data["amount"].IsUint64())
            {
                connection->close();
                ASKCOIN_RETURN;
            }
                    
            uint64 amount = data["amount"].GetUint64();
                    
            if(amount == 0)
            {
                connection->close();
                ASKCOIN_RETURN;
            }
                    
            if(!data.HasMember("reply_to"))
            {
                connection->close();
                ASKCOIN_RETURN;
            }
                    
            if(!data["reply_to"].IsString())
            {
                connection->close();
                ASKCOIN_RETURN;
            }
                    
            std::string reply_to_key = data["reply_to"].GetString();
                        
            if(!is_base64_char(reply_to_key))
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(reply_to_key.length() != 44)
            {
                connection->close();
                ASKCOIN_RETURN;
            }

            if(account->get_balance() < 2 + account->m_uv_spend + amount)
            {
                rsp_doc.AddMember("err_code", net::api::ERR_BALANCE_NOT_ENOUGH, allocator);
                connection->send(rsp_doc);
                ASKCOIN_RETURN;
            }
                    
            std::shared_ptr<Topic> topic;
            
            if(!get_topic(topic_key, topic))
            {
                rsp_doc.AddMember("err_code", net::api::ERR_TOPIC_NOT_EXIST, allocator);
                connection->send(rsp_doc);
                ASKCOIN_RETURN;
            }

            uint64 topic_block_id = topic->m_block->id();
            
            if(topic_block_id + TOPIC_LIFE_TIME < cur_block_id + 1)
            {
                rsp_doc.AddMember("err_code", net::api::ERR_TOPIC_NOT_EXIST, allocator);
                connection->send(rsp_doc);
                ASKCOIN_RETURN;
            }
            
            if(topic->get_owner() != account)
            {
                connection->close();
                ASKCOIN_RETURN;
            }
                    
            if(topic->m_reply_list.size() + topic->m_uv_reply >= 1000)
            {
                rsp_doc.AddMember("err_code", net::api::ERR_REPLY_NUM_EXCEED_LIMIT, allocator);
                connection->send(rsp_doc);
                ASKCOIN_RETURN;
            }
            
            if(topic->get_balance() < amount + topic->m_uv_reward)
            {
                rsp_doc.AddMember("err_code", net::api::ERR_TOPIC_BALANCE_NOT_ENOUGH, allocator);
                connection->send(rsp_doc);
                ASKCOIN_RETURN;
            }
            
            std::shared_ptr<Reply> reply_to;
            
            if(!topic->get_reply(reply_to_key, reply_to))
            {
                rsp_doc.AddMember("err_code", net::api::ERR_REPLY_NOT_EXIST, allocator);
                connection->send(rsp_doc);
                ASKCOIN_RETURN;
            }
            
            if(reply_to->type() != 0)
            {
                connection->close();
                ASKCOIN_RETURN;
            }
            
            std::shared_ptr<tx::Tx_Reward> tx_reward(new tx::Tx_Reward);
            tx_reward->m_id = tx_id;
            tx_reward->m_type = 5;
            tx_reward->m_utc = utc;
            tx_reward->m_doc = doc_ptr;
            tx_reward->m_pubkey = pubkey;
            tx_reward->m_block_id = block_id;
            tx_reward->m_amount = amount;
            tx_reward->m_topic_key = topic_key;
            tx_reward->m_reply_to = reply_to_key;
            m_uv_tx_ids.insert(tx_id);
            account->m_uv_spend += 2;
            topic->m_uv_reward += amount;
            topic->m_uv_reply += 1;
            m_uv_2_txs.push_back(tx_reward);
            net::p2p::Node::instance()->broadcast(p2p_doc);
            connection->send(rsp_doc);
        }
        else
        {
            connection->close();
            ASKCOIN_RETURN;
        }
    }
}
