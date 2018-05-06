#ifndef ACCUM_POW
#define ACCUM_POW

#include <array>
#include "fly/base/common.hpp"

class Accum_Pow
{
public:
    Accum_Pow();
    void add_pow(uint32 zero_bits);
    bool operator<(const Accum_Pow &other);
    
private:
    std::array<uint64, 9> m_n32;
};

#endif
