#ifndef TOPIC
#define TOPIC

#include <list>
#include <memory>
#include <unordered_map>
#include "fly/base/common.hpp"
#include "reply.hpp"

class Account;

class Topic
{
public:
    Topic(std::string key, std::string data, std::string block_hash, uint64 balance);
    ~Topic();
    void set_owner(std::shared_ptr<Account> owner);
    std::shared_ptr<Account> get_owner();
    const std::string& block_hash();
    const std::string& key();
    bool get_reply(std::string key, std::shared_ptr<Reply> &reply);
    bool add_member(std::string tx_id, std::shared_ptr<Account> account);
    void sub_balance(uint64 value);
    void add_balance(uint64 value);
    uint64 get_balance();
    uint64 get_total();
    std::list<std::shared_ptr<Reply>> m_reply_list;
    std::list<std::pair<std::string, std::shared_ptr<Account>>> m_members;
    uint32 m_uv_reply;
    uint64 m_uv_reward;
    
private:
    std::string m_data;
    std::string m_key;
    std::string m_block_hash;
    uint64 m_balance;
    uint64 m_total;
    std::shared_ptr<Account> m_owner;
};

#endif
