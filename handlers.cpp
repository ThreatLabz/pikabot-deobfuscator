#include "handlers.hpp"

int handlers::DecryptPikabotString::visit_minsn()
{
	if (!heuristic::isRC4Encrypted(*curins))
		return 0;
	msg("[+] Searching for the size of encrypted array at: %x\n", curins->ea);
	size_t encryptedRC4StringSize = m_Decrypter.getRC4EncryptedStringSize(blk);
	if (!encryptedRC4StringSize)
		return 0;
	std::vector<unsigned char> encryptedArray = m_Decrypter.getEncryptedArray(curins, blk, encryptedRC4StringSize);
	if (encryptedArray.empty())
		return 0;
	std::string decryptedRC4String;
	for (auto& [keyAddress, RC4Key] : m_rc4Keys)
	{
		if (std::find(m_RC4SuccessfullKeysAddresses.begin(), m_RC4SuccessfullKeysAddresses.end(), keyAddress) != m_RC4SuccessfullKeysAddresses.end())
			continue;
		decryptedRC4String = m_Decrypter.decryptRC4String(encryptedArray, RC4Key.data(), encryptedRC4StringSize);
		if (!decryptedRC4String.empty())
		{
			m_RC4DecryptedStrings.push_back(decryptedRC4String);
			m_RC4SuccessfullKeysAddresses.push_back(keyAddress);
			break;
		}
	}
	if (decryptedRC4String.empty())
	{
		msg("[-] Failed to decrypt with any of RC4 candidate keys at: %x\n", curins->ea);
		return 0;
	}
	std::string decryptedAESString = m_Decrypter.decryptAESString(decryptedRC4String);
	if (!decryptedAESString.empty())
	{
		decryptedStrings[curins->ea] = decryptedAESString.c_str();
		return 0;
	}
	std::vector<std::string> decryptedCNCs = m_Decrypter.decryptCNCs(decryptedRC4String);
	if (decryptedCNCs.empty())
	{
		decryptedStrings[curins->ea] = decryptedRC4String.c_str();
		msg("[!] Failed to AES decrypt at: %x. Using RC4 decrypted string as a comment\n", curins->ea);
		return 0;
	}
	std::ostringstream concatenatedCNCs;
	std::copy(decryptedCNCs.begin(), decryptedCNCs.end(),
		std::ostream_iterator<std::string>(concatenatedCNCs, "\r\n"));
	decryptedStrings[curins->ea] = concatenatedCNCs.str();
	return 0;
}

int handlers::getAllRC4Keys::visit_minsn()
{
	if (curins->opcode == m_call && curins->l.t == mop_h && !qstrcmp(curins->l.helper, "strcpy") &&
		curins->d.t == mop_f && utils::validateCopyFunction(curins) && curins->d.f->args[1].t == mop_str)
	{
		m_rc4Keys[curins->ea] = curins->d.f->args[1].cstr;
	}
	else if (curins->opcode == m_mov && curins->l.t == mop_v && curins->d.t == mop_S && curins->l.g != 0)
	{
		unsigned char sourceString[50] = { 0 };
		// Should be enough to cover all cases.
		size_t readBytes = get_bytes(sourceString, 50, curins->l.g);
		if (readBytes > 0 && utils::isPrintableAscii(sourceString))
			m_rc4Keys[curins->ea] = reinterpret_cast<char*>(sourceString);
	}
	return 0;

}

void handlers::decryptAllStrings(pluginCtx* plugin)
{
	for (size_t i = 0; i < get_func_qty(); i++)
	{
		func_t* currentFunction = getn_func(i);
		mba_ranges_t mbr(currentFunction);
		hexrays_failure_t hexraysFailure;
		mbl_array_t* mba = gen_microcode(mbr, &hexraysFailure);
		if (mba == nullptr)
		{
			msg("[-] Failed to decompile at: %x - with error: %s\n", currentFunction->start_ea, hexraysFailure.desc().c_str());
			continue;
		}
		getAllRC4Keys getRC4Keys;
		mba->for_all_topinsns(getRC4Keys);
		if (getRC4Keys.m_rc4Keys.empty())
		{
			delete mba;
			continue;
		}
		DecryptPikabotString visitor(plugin->decrypter, getRC4Keys.m_rc4Keys);
		mba->for_all_topinsns(visitor);
		if (visitor.decryptedStrings.empty())
		{
			delete mba;
			continue;
		}
		cfuncptr_t cfunc = create_cfunc(mba);
		for (auto const& [address, decryptedString] : visitor.decryptedStrings)
		{
			utils::setDecompilerComment(*cfunc, address, decryptedString);
		}
		cfunc->save_user_cmts();
		cfunc->refresh_func_ctext();
		visitor.decryptedStrings.clear();
	}
	msg("[+] Plugin task completed\n");
}

bool handlers::extractAESInfo(pluginCtx* plugin)
{
	if (!plugin->decrypter.m_AESKey.empty() && !plugin->decrypter.m_AESIV.empty())
	{
		msg("[+] AES info function already found. Current AES key/IV %s - %s\n", plugin->decrypter.m_AESKey.c_str(), plugin->decrypter.m_AESIV.c_str());
		return true;
	}
	for (size_t i = 0; i < get_func_qty(); i++)
	{
		func_t* currentFunction = getn_func(i);
		// We limit the block size that we scan
		if (currentFunction->size() < 600 || currentFunction->size() > 1600)
			continue;
		mba_ranges_t mbr(currentFunction);
		hexrays_failure_t hexraysFailure;
		mbl_array_t* mba = gen_microcode(mbr, &hexraysFailure);
		if (mba == nullptr)
		{
			msg("[-] Failed to decompile at: %x - with error: %s\n", currentFunction->start_ea, hexraysFailure.desc().c_str());
			continue;
		}
		msg("[+] Scanning function %x for AES/IV with size: %d\n", currentFunction->start_ea, currentFunction->size());
		if (heuristic::isAESBlock(*mba))
		{
			msg("[+] Found AES func at: %x\n", currentFunction->start_ea);
			getAllRC4Keys getRC4Keys;
			mba->for_all_topinsns(getRC4Keys);
			if (getRC4Keys.m_rc4Keys.empty())
			{
				msg("[-] Failed to extract RC4 keys candidates in AES function\n");
				delete mba;
				return false;
			}
			DecryptPikabotString visitor(plugin->decrypter, getRC4Keys.m_rc4Keys);
			mba->for_all_topinsns(visitor);
			if (visitor.m_RC4DecryptedStrings.empty() || visitor.m_RC4DecryptedStrings.size() != 2)
			{
				msg("[!] Incorrect number of decrypted strings during AES searching.\n");
				delete mba;
				return false;
			}
			else
			{
				std::string AESKey = *std::max_element(visitor.m_RC4DecryptedStrings.begin(), visitor.m_RC4DecryptedStrings.end(), [](const auto& firstElement, const auto& secondElement) {
					return firstElement.size() < secondElement.size(); });
				std::erase(visitor.m_RC4DecryptedStrings, AESKey);
				AESKey = AESKey.substr(0, 32);
				plugin->decrypter.m_AESKey = AESKey;
				std::string AESIV = visitor.m_RC4DecryptedStrings.front();
				AESIV = AESIV.substr(0, 16);
				plugin->decrypter.m_AESIV = AESIV;
				msg("[+] AES key: %s and IV %s\n", AESKey.c_str(), AESIV.c_str());
				delete mba;
				return true;
			}
		}
		delete mba;
	}
	msg("[-] Failed to detect AES key/IV\n");
	return false;
}