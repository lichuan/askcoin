#ifndef TRANSACTION
#define TRANSACTION

#include "fly/base/common.hpp"

class Transaction
{
public:
    enum TYPE
    {
        INVALID = 0,
        VOTE_PARAMS = 1,
        BLOCK_REWARD = 2,
        REG_ACCOUNT = 3,
        SEND_COIN = 4,
        MAX
    };
    
    Transaction();
    uint32 version();
    TYPE type();
    uint64 block_id();
    std::string get_save_string();
    void restore_from_string(std::string data);
};

#endif
