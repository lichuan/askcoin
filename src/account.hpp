#ifndef ACCOUNT
#define ACCOUNT

#include <list>
#include "fly/base/common.hpp"
#include "history.hpp"

class Account
{
public:
    Account(uint64 id, std::string name, std::string pubkey, uint32 avatar);
    ~Account();
    std::string pubkey();
    void set_balance(uint64 value);
    void add_balance(uint64 value);
    void sub_balance(uint64 value);
    uint64 get_balance();
    void add_history(History *history);

private:
    std::list<History*> m_history;
    std::string m_name;
    uint64 m_id;
    std::string m_pubkey;
    uint64 m_balance;
    std::string m_referrer;
    uint32 m_avatar;
};

#endif
