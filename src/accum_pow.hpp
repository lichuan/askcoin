#ifndef ACCUM_POW
#define ACCUM_POW

#include <array>
#include "fly/base/common.hpp"

class Accum_Pow
{
public:
    Accum_Pow();
    Accum_Pow(uint64 v0, uint64 v1, uint64 v2, uint64 v3, uint64 v4, uint64 v5, uint64 v6, uint64 v7, uint64 v8);
    void add_pow(uint32 zero_bits);
    bool operator>(const Accum_Pow &other);
    bool operator==(const Accum_Pow &other);
    
private:
    std::array<uint64, 9> m_n32;
};

#endif
