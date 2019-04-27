#ifndef REPLY
#define REPLY

#include <list>
#include <memory>
#include "fly/base/common.hpp"
#include "block.hpp"

class Account;

class Reply
{
public:
    Reply(std::string key, uint32 type, std::shared_ptr<Block> block, std::string data);
    ~Reply();
    void set_owner(std::shared_ptr<Account> owner);
    std::shared_ptr<Account> get_owner();
    const std::string& key();
    void set_reply_to(std::shared_ptr<Reply> to);
    std::shared_ptr<Reply> get_reply_to();
    void add_balance(uint64 value);
    void sub_balance(uint64 value);
    void set_balance(uint64 balance);
    uint64 get_balance();
    uint32 type();
    std::string m_data;
    std::shared_ptr<Block> m_block;
    
private:
    std::string m_key;
    uint32 m_type; // 0 normal reply, 1 reward
    uint64 m_balance;
    std::shared_ptr<Account> m_owner;
    std::shared_ptr<Reply> m_to;
};

#endif
