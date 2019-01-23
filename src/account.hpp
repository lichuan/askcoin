#ifndef ACCOUNT
#define ACCOUNT

#include <list>
#include <memory>
#include "fly/base/common.hpp"
#include "topic.hpp"
#include "history.hpp"

class Account : public std::enable_shared_from_this<Account>
{
public:
    struct Rich_Comp
    {
        bool operator()(const std::shared_ptr<Account> &a, const std::shared_ptr<Account> &b)
        {
            if(a->get_balance() > b->get_balance())
            {
                return true;
            }

            if(a->get_balance() < b->get_balance())
            {
                return false;
            }
            
            return a->id() < b->id();
        }
    };
    
    Account(uint64 id, std::string name, std::string pubkey, uint32 avatar, uint64 block_id);
    ~Account();
    const std::string& pubkey();
    uint64 id();
    const std::string& name();
    uint32 avatar();
    void set_balance(uint64 value);
    void add_balance(uint64 value);
    void sub_balance(uint64 value);
    void set_referrer(std::shared_ptr<Account> account);
    std::shared_ptr<Account> get_referrer();
    uint64 get_balance();
    uint64 block_id();
    void add_history(std::shared_ptr<History> history);
    void pop_history();
    void pop_history_for_explorer();
    void proc_history_expired(uint64 cur_block_id);
    bool joined_topic(std::shared_ptr<Topic> topic);
    void leave_topic(std::shared_ptr<Topic> topic);
    std::list<std::shared_ptr<Topic>> m_topic_list;
    std::list<std::shared_ptr<Topic>> m_joined_topic_list;
    std::list<std::shared_ptr<History>> m_history;
    std::list<std::shared_ptr<History>> m_history_for_explorer;
    uint64 m_uv_spend;
    uint32 m_uv_topic;
    uint32 m_uv_join_topic;
    
private:
    std::string m_name;
    uint64 m_id;
    uint64 m_block_id;
    std::string m_pubkey;
    uint64 m_balance;
    std::shared_ptr<Account> m_referrer;
    uint32 m_avatar;
};

#endif
