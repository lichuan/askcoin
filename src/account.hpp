#ifndef ACCOUNT
#define ACCOUNT

#include <list>
#include <memory>
#include "fly/base/common.hpp"
#include "topic.hpp"
#include "history.hpp"

class Account
{
public:
    struct Rich_Comp
    {
        bool operator()(const std::shared_ptr<Account> &a, const std::shared_ptr<Account> &b)
        {
            return a->get_balance() > b->get_balance();
        }
    };
    
    Account(uint64 id, std::string name, std::string pubkey, uint32 avatar);
    ~Account();
    std::string pubkey();
    uint64 id();
    std::string name();
    void set_balance(uint64 value);
    void add_balance(uint64 value);
    void sub_balance(uint64 value);
    void set_referrer(std::shared_ptr<Account> account);
    std::shared_ptr<Account> get_referrer();
    uint64 get_balance();
    void add_history(History *history);
    bool join_topic(std::shared_ptr<Topic> topic);
    std::list<std::shared_ptr<Topic>> m_topic_list;
    std::list<std::shared_ptr<Topic>> m_joined_topic_list;
    
private:
    std::list<History*> m_history;
    std::string m_name;
    uint64 m_id;
    std::string m_pubkey;
    uint64 m_balance;
    std::shared_ptr<Account> m_referrer;
    uint32 m_avatar;
};

#endif
