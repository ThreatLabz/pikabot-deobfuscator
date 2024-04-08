#include "decrypter.hpp"

std::vector<std::string> Decrypter::decryptCNCs(std::string input)
{
	std::string cncAESKey;
	std::string cncAESIV;
	std::string decryptedCNC;
	std::string encryptedCNC;
	std::string token;
	std::vector<std::string> decryptedCNCs;
	std::stringstream inputStream(input);

	size_t delimiter_occurences = std::count_if(input.begin(), input.end(), [](char delimiter) {return delimiter == '&'; });
	if (delimiter_occurences < 1 || input.length() < 48)
		return decryptedCNCs;
	while (getline(inputStream, token, '&'))
	{
		std::replace(token.begin(), token.end(), '_', '=');
		cncAESKey = token.substr(3, 16);
		cncAESKey += token.substr(token.size() - 16);
		cncAESIV = token.substr(19, 16);
		encryptedCNC = token.substr(35, token.size() - cncAESKey.size() - cncAESIV.size() - 3);
		size_t decodedBase64Length = decode_base64((unsigned char*)encryptedCNC.data());
		if (!decodedBase64Length || (decodedBase64Length % 16) || encryptedCNC.empty() || cncAESKey.empty() || cncAESIV.empty())
			continue;
		unsigned char* decryptedString = utils::decryptAESCBC(reinterpret_cast<unsigned char*>(cncAESKey.data()), reinterpret_cast<unsigned char*>(cncAESIV.data()),
			reinterpret_cast<unsigned char*>(encryptedCNC.data()), decodedBase64Length);
		if (!utils::isPrintableAscii(decryptedString))
		{
			error("[-] Failed to decrypt CNC\n");
			delete[] decryptedString;
			return decryptedCNCs;
		}
		decryptedCNC = reinterpret_cast<char*>(decryptedString);
		msg("[+] Decrypted CNC: %s\n", decryptedCNC.c_str());
		decryptedCNCs.push_back(decryptedCNC);
		delete[] decryptedString;
	}
	return decryptedCNCs;
}

struct FindEncryptedArray : public mop_visitor_t
{
	size_t m_EncryptedStringSize = 0;
	std::vector<unsigned char> m_EncryptedArrayVec;

	int idaapi visit_mop(mop_t* op, const tinfo_t* type, bool is_target) override
	{
		mblock_t* initialBlock = blk;
		minsn_t* functionHead = blk->prevb->head;
		mblock_t* loopBlock = blk->prevb;
		sval_t stackOffset = 0;
		if (op->t == mop_S && curins->opcode == m_add)
		{
			op->get_stkoff(&stackOffset);
			uint32 functionStartAddress = get_func(blk->head->ea)->start_ea;
			while (functionHead != nullptr)
			{
				for (minsn_t* instruction = functionHead; instruction != nullptr; instruction = instruction->next)
				{
					if (instruction->opcode == m_mov && instruction->l.t == mop_n && instruction->d.t == mop_S)
					{
						sval_t currentStackOffset = 0;
						instruction->d.get_stkoff(&currentStackOffset);
						if (currentStackOffset == stackOffset)
						{
							// Reset
							loopBlock = initialBlock;
							stackOffset += instruction->l.size;
							msg("[+] Found part of encrypted array at: %x with value: %x\n", instruction->ea, instruction->l.nnn->value);
							utils::pushIntegerToVector(m_EncryptedArrayVec, instruction->l.nnn->value, instruction->l.size);
							break;
						}
					}
					else if (instruction->opcode == m_call && instruction->l.t == mop_h && instruction->d.t == mop_f && utils::validateCopyFunction(instruction)
						&& instruction->d.f->args[0].t == mop_a && (sval_t)instruction->d.f->args[0].a->nnn->value == stackOffset)
					{
						size_t sourceDataSize = 0;
						if (!qstrcmp(instruction->l.helper, "memcpy"))
						{
							sourceDataSize = instruction->d.f->args[2].nnn->value;
						}
						else {
							sourceDataSize = instruction->d.f->args[1].size;
						}
						stackOffset += sourceDataSize;
						// In case of cncs, the encrypted arrays can be stored in a global var.
						if (!qstrcmp(instruction->l.helper, "memcpy") && instruction->d.f->args[1].t == mop_a && instruction->d.f->args[1].is_glbaddr()
							&& instruction->d.f->args[2].nnn->value == m_EncryptedStringSize && m_EncryptedStringSize > 0)
						{
							msg("[+] Potential encrypted CNCs detected at: %x\n", instruction->ea);
							unsigned char* encryptedCNCsBuffer = (unsigned char*)malloc(m_EncryptedStringSize);
							memset(encryptedCNCsBuffer, 0, m_EncryptedStringSize);
							if (get_bytes(encryptedCNCsBuffer, m_EncryptedStringSize, instruction->d.f->args[1].nnn->value))
								m_EncryptedArrayVec.insert(m_EncryptedArrayVec.end(), encryptedCNCsBuffer, encryptedCNCsBuffer + m_EncryptedStringSize);
							free(encryptedCNCsBuffer);
							return m_EncryptedArrayVec.size();
						}
						char* functionSourceString = instruction->d.f->args[1].cstr;
						if (strlen(functionSourceString) != sourceDataSize && sourceDataSize > 0)
						{
							std::string parsedString = utils::parseEscapedString(functionSourceString);
							utils::pushToVector(m_EncryptedArrayVec, parsedString);
							utils::padEncryptedArray(m_EncryptedArrayVec, parsedString.size(), sourceDataSize);
						}
						else {
							utils::pushToVector(m_EncryptedArrayVec, functionSourceString);
						}
						loopBlock = initialBlock;
						break;
					}
				}
				if (functionHead == nullptr || functionHead->ea == functionStartAddress || m_EncryptedStringSize == m_EncryptedArrayVec.size())
					break;
				loopBlock = loopBlock->prevb;
				functionHead = loopBlock->head;
			}
		}
		if (m_EncryptedArrayVec.size() == m_EncryptedStringSize)
			return true;
		return false;
	}
};

std::vector<unsigned char> Decrypter::getEncryptedArray(minsn_t* insn, mblock_t* block, const size_t& encryptedStringSize)
{
	FindEncryptedArray searchEncryptedArray;
	searchEncryptedArray.blk = block;
	searchEncryptedArray.m_EncryptedStringSize = encryptedStringSize;
	if (!insn->for_all_ops(searchEncryptedArray))
	{
		error("[-] Failed to extract encrypted array. Got incorrect size of: %d\n", searchEncryptedArray.m_EncryptedArrayVec.size());
		return {};
	}
	return searchEncryptedArray.m_EncryptedArrayVec;
}

size_t Decrypter::getRC4EncryptedStringSize(mblock_t* block)
{
	for (minsn_t* instruction = block->tail; instruction != nullptr; instruction = instruction->prev)
	{
		if ((instruction->opcode == m_jb || instruction->opcode == m_jae || instruction->opcode == m_setb) && instruction->r.t == mop_n)
		{
			msg("[+] Found encrypted array size: %d\n", instruction->r.nnn->value);
			return instruction->r.nnn->value;
		}
	}
	msg("[-] Failed to extract encrypted array size\n");
	return 0;
}

std::string Decrypter::decryptAESString(std::string inputString)
{
	std::string aesdecryptedString;
	if (m_AESKey.empty() || m_AESIV.empty())
	{
		msg("[-] AES key/IV not set\n");
		return aesdecryptedString;
	}
	std::replace(inputString.begin(), inputString.end(), '_', '=');
	size_t decodedBase64Length = decode_base64(reinterpret_cast<unsigned char*>(inputString.data()));
	if (decodedBase64Length && !(decodedBase64Length % 16))
	{
		unsigned char* decryptedString = utils::decryptAESCBC(reinterpret_cast<unsigned char*>(m_AESKey.data()),
			reinterpret_cast<unsigned char*>(m_AESIV.data()), reinterpret_cast<unsigned char*>(inputString.data()), decodedBase64Length);
		if (utils::isPrintableAscii(decryptedString))
		{
			msg("[+] Decrypted string: %s\n", decryptedString);
			aesdecryptedString = reinterpret_cast<char*>(decryptedString);
			delete[] decryptedString;
			return aesdecryptedString;
		}
		delete[] decryptedString;
	}
	return aesdecryptedString;
}

std::string Decrypter::decryptRC4String(std::vector<unsigned char> encryptedArray, char* RC4Key, const size_t& encryptedRC4StringSize)
{
	std::string decryptedString;
	if (!RC4Key)
		return decryptedString;
	std::string parsedRC4Key;
	utils::unescapeString(RC4Key, parsedRC4Key);
	if (!parsedRC4Key.length())
		return {};
	utils::rc4_state RC4Ctx = { 0 };
	utils::rc4_setup(&RC4Ctx, reinterpret_cast<unsigned char*>(parsedRC4Key.data()), parsedRC4Key.length());
	utils::rc4_crypt(&RC4Ctx, encryptedArray.data(), encryptedArray.size());
	encryptedArray.push_back(0);
	decryptedString = reinterpret_cast<char*>(encryptedArray.data());
	if (utils::isPrintableAscii(encryptedArray.data()) && decryptedString.length() == encryptedRC4StringSize)
	{
		msg("[+] RC4 decrypted string: %s with key %s\n", decryptedString.c_str(), RC4Key);
		return decryptedString;
	}
	msg("[-] RC4 decryption failed with key %s\n", parsedRC4Key.c_str());
	return {};
}