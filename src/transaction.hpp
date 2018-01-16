#ifndef TRANSACTION
#define TRANSACTION

#include "fly/base/common.hpp"

enum TX_TYPE
{
    INVALID = 0,
    APPLY_WITNESS = 1,
    VOTE_WITNESS = 2,
    VOTE_PARAMS = 3,
    BLOCK_REWARD = 4,
    REG_ACCOUNT = 5
};

class Transaction
{
public:
    Transaction();
    uint32 version();
    TX_TYPE type();
    uint64 block_id();
    std::string get_save_string();
    void restore_from_string(std::string data);
};

#endif
