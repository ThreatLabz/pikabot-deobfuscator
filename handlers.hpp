#pragma once
#include "plugin.hpp"

namespace handlers
{
	/*
	* Decrypts a detected Pikabot string. The following steps are taken:
	* 1) Detects the size of the encrypted array.
	* 2) Detects and extracts the RC4 key.
	* 3) Detects and extracts the RC4-Encrypted array.
	* 4) Decrypts the encrypted array using RC4 followed by AES.
	* 5) In case of CNCs, it parses them.
	*/
	struct ida_local DecryptPikabotString : public minsn_visitor_t
	{
		Decrypter& m_Decrypter;
		std::vector<std::string> m_RC4DecryptedStrings;
		std::vector<unsigned long long> m_RC4SuccessfullKeysAddresses;
		std::map<unsigned long long, std::string> m_rc4Keys;
		std::map<unsigned int, std::string> decryptedStrings;
		DecryptPikabotString(Decrypter& mDecrypter, std::map<unsigned long long, std::string> rc4keys) : m_Decrypter(mDecrypter), m_rc4Keys(rc4keys) {}
		int visit_minsn() override;
	};

	// Extract all inlined strings from a function and use them as RC4 keys.
	struct ida_local getAllRC4Keys : public minsn_visitor_t
	{
		std::map<unsigned long long, std::string> m_rc4Keys;
		int visit_minsn() override;
	};

	void decryptAllStrings(pluginCtx* plugin);

	// Extract the AES key/IV, which are used for decrypting the last layer of each string.
	bool extractAESInfo(pluginCtx* plugin);
}