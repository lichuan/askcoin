#ifndef BLOCK
#define BLOCK

#include "transaction.hpp"

class Block
{
public:
    Block();
    std::string get_save_string();
    void restore_from_string(std::string data);
};

#endif
