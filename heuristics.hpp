#pragma once
#include <hexrays.hpp>
#include "ida.hpp"

namespace heuristic
{
	// Similar methodology as used in Goomba plugin.
	bool isRC4Encrypted(const minsn_t& insn);
	bool isAESBlock(const mbl_array_t& mba);
}