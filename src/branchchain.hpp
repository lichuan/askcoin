#ifndef BRANCHCHAIN
#define BRANCHCHAIN

#include <string>
#include <memory>
#include <unordered_set>
#include <unordered_map>
#include "fly/base/singleton.hpp"
#include "block.hpp"
#include "account.hpp"

class Branchchain
{
public:
    Branchchain();
    ~Branchchain();
    
private:
    uint64 m_cur_db_block_id;
    std::unordered_set<std::string> m_account_name_set;
};

#endif
