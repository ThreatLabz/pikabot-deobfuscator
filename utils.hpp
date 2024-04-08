#pragma once
#include <sstream>
#include <hexrays.hpp>
#include "aes.hpp"

namespace utils
{
	struct rc4_state
	{
		int x, y, m[256];
	};
	void setDecompilerComment(cfunc_t& cfunc, unsigned long address, const std::string& decryptedString);
	void pushIntegerToVector(std::vector<unsigned char>& vec, unsigned long long input, const size_t len);
	bool isPrintableAscii(unsigned char* str);
	bool validateCopyFunction(minsn_t* p);
	void unescapeString(char* input, std::string& parsedRC4Key);
	void unpad(unsigned char* input, const size_t arr_len);
	void rc4_setup(struct rc4_state* s, unsigned char* key, int length);
	void rc4_crypt(struct rc4_state* s, unsigned char* data, int length);
	unsigned char* decryptAESCBC(const unsigned char* AESKey, const unsigned char* AESIV, const unsigned char* input, const size_t& inputLength);
	// Ugly hack to parse characters, which have been already escaped by IDA. e.g. t\n
	std::string parseEscapedString(char* input);
	void padEncryptedArray(std::vector<unsigned char>& vectorInput, const size_t parsedStringSize, const size_t expectedSize);
	void pushToVector(std::vector<unsigned char>& m_EncryptedArrayVec, const std::string& parsedString);
}