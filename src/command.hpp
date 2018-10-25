#ifndef COMMAND
#define COMMAND

#include "fly/base/common.hpp"

class Command
{
public:
    Command()
    {
        m_param_num = 0;
    }
    
    std::string m_cmd;
    std::string m_params[3];
    uint32 m_param_num;
};

#endif
