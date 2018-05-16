#ifndef REPLY
#define REPLY

#include <list>
#include <memory>
#include "fly/base/common.hpp"

class Account;

class Reply
{
public:
    Reply(std::string key, uint32 type, std::string data);
    ~Reply();
    void set_owner(std::shared_ptr<Account> owner);
    std::shared_ptr<Account> get_owner();
    void set_reply_to(std::shared_ptr<Reply> to);
    std::shared_ptr<Reply> get_reply_to();
    void add_balance(uint64 value);
    uint64 get_balance();
    
private:
    std::string m_key;
    uint32 m_type; // 0 normal reply, 1 reward
    std::string m_data;
    uint64 m_balance;
    std::shared_ptr<Account> m_owner;
    std::shared_ptr<Reply> m_to;
};

#endif
