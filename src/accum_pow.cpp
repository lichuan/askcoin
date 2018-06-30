#include "accum_pow.hpp"

Accum_Pow::Accum_Pow()
{
    m_n32.fill(0);
}

Accum_Pow::Accum_Pow(uint64 v0, uint64 v1, uint64 v2, uint64 v3, uint64 v4, uint64 v5, uint64 v6, uint64 v7, uint64 v8)
    : m_n32{v0, v1, v2, v3, v4, v5, v6, v7, v8}
{
}

void Accum_Pow::add_pow(uint32 zero_bits)
{
    uint32 idx = zero_bits / 32;
    uint32 remain = zero_bits % 32;
    const uint64 max_u32 = (uint64)1 << 32;
    m_n32[idx] += (uint64)1 << remain;
    
    while(m_n32[idx] >= max_u32)
    {
        m_n32[idx] -= max_u32;
        m_n32[idx + 1] += 1;
        idx += 1;
    }
}

bool Accum_Pow::sub_pow(uint32 zero_bits)
{
    uint32 idx = zero_bits / 32;
    uint32 remain = zero_bits % 32;
    const uint64 max_u32 = (uint64)1 << 32;
    uint64 v = (uint64)1 << remain;
    auto n32 = m_n32;

    if(m_n32[idx] < v)
    {
        m_n32[idx] = m_n32[idx] + max_u32 - v;
        
        while(++idx <= 8)
        {
            if(m_n32[idx] == 0)
            {
                m_n32[idx] = max_u32 - 1;
            }
            else
            {
                m_n32[idx] -= 1;

                return true;
            }
        }

        m_n32 = n32;

        return false;
    }

    m_n32[idx] -= v;

    return true;
}

bool Accum_Pow::operator==(const Accum_Pow &other)
{
    return m_n32 == other.m_n32;
}

bool Accum_Pow::operator>(const Accum_Pow &other)
{
    if(m_n32[8] > other.m_n32[8])
    {
        return true;
    }

    if(m_n32[8] < other.m_n32[8])
    {
        return false;
    }

    if(m_n32[7] > other.m_n32[7])
    {
        return true;
    }

    if(m_n32[7] < other.m_n32[7])
    {
        return false;
    }

    if(m_n32[6] > other.m_n32[6])
    {
        return true;
    }

    if(m_n32[6] < other.m_n32[6])
    {
        return false;
    }

    if(m_n32[5] > other.m_n32[5])
    {
        return true;
    }

    if(m_n32[5] < other.m_n32[5])
    {
        return false;
    }

    if(m_n32[4] > other.m_n32[4])
    {
        return true;
    }

    if(m_n32[4] < other.m_n32[4])
    {
        return false;
    }

    if(m_n32[3] > other.m_n32[3])
    {
        return true;
    }

    if(m_n32[3] < other.m_n32[3])
    {
        return false;
    }

    if(m_n32[2] > other.m_n32[2])
    {
        return true;
    }

    if(m_n32[2] < other.m_n32[2])
    {
        return false;
    }

    if(m_n32[1] > other.m_n32[1])
    {
        return true;
    }

    if(m_n32[1] < other.m_n32[1])
    {
        return false;
    }
    
    return m_n32[0] > other.m_n32[0];
}
