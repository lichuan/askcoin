#ifndef BLOCKCHAIN
#define BLOCKCHAIN

#include <string>
#include "fly/base/singleton.hpp"
#include "block.hpp"

class Blockchain : public fly::base::Singleton<Blockchain>
{
public:
    Blockchain();
    ~Blockchain();
    bool load(std::string db_path);
};

#endif
