#include "heuristics.hpp"

struct DetectRC4Encryption : public minsn_visitor_t
{
    bool m_StxFound = false;
    bool m_XorFound = false;
    int visit_minsn(void) override
    {
        switch (curins->opcode)
        {
        case m_xor:
            m_XorFound = true;
            break;
        case m_stx:
            m_StxFound = true;
            break;
        default:
            return 0;
        }
        return m_StxFound && m_XorFound;
    }
};

bool heuristic::isRC4Encrypted(const minsn_t& insn)
{
    DetectRC4Encryption visitor;
    return CONST_CAST(minsn_t*)(&insn)->for_all_insns(visitor) && insn.has_side_effects(true);
}

struct isAesFunction : minsn_visitor_t
{
    bool m_StxFound = false;
    bool m_JnzFound = false;
    bool m_RC4Found = false;

    int visit_minsn() override
    {
        if (curins->opcode == m_stx && curins->l.t == mop_n && curins->l.nnn->value == 0x3D)
            m_StxFound = true;
        else if (curins->opcode == m_jnz && curins->r.t == mop_n && curins->r.nnn->value == 0x5F)
            m_JnzFound = true;
        else if (heuristic::isRC4Encrypted(*curins))
            m_RC4Found = true;
        if (m_StxFound && m_JnzFound && m_RC4Found)
            return 1;
        return 0;
    }
};

bool heuristic::isAESBlock(const mbl_array_t& mba)
{
    isAesFunction visitor;
    return CONST_CAST(mbl_array_t*)(&mba)->for_all_topinsns(visitor);
}