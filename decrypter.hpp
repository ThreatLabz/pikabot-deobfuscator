#pragma once
#include <loader.hpp>
#include <funcs.hpp>
#include "base64.hpp"
#include "heuristics.hpp"
#include "utils.hpp"

class Decrypter
{
public:
	// Parses and decrypts the CNCs. The CNCs list is splitted based on the delimiter `&`
	std::vector<std::string> decryptCNCs(std::string input);
	// Decrypts a RC4 string
	std::string decryptRC4String(std::vector<unsigned char> encryptedArray, char* RC4Key, const size_t& encryptedRC4StringSize);
	// Decrypts a AES string
	std::string decryptAESString(std::string inputString);
	size_t getRC4EncryptedStringSize(mblock_t* block);
	std::vector<unsigned char> getEncryptedArray(minsn_t* insn, mblock_t* block, const size_t& encryptedStringSize);
	std::string m_AESKey;
	std::string m_AESIV;
};