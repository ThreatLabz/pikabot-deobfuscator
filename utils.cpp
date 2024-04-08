#include "utils.hpp"

void utils::pushToVector(std::vector<unsigned char>& m_EncryptedArrayVec, const std::string& parsedString)
{
	for (size_t i = 0; i < parsedString.size(); i++)
	{
		m_EncryptedArrayVec.push_back(static_cast<unsigned char>(parsedString[i]));
	}
}

void utils::padEncryptedArray(std::vector<unsigned char>& vectorInput, const size_t parsedStringSize, const size_t expectedLength)
{
	if (parsedStringSize < expectedLength)
	{
		int padLength = expectedLength - parsedStringSize;
		for (size_t i = 0; i < padLength; i++)
			vectorInput.push_back('\0');
	}
}

bool utils::validateCopyFunction(minsn_t* instruction)
{
	mcallinfo_t* callInfo = instruction->d.f;
	if (!callInfo)
	{
		error("[-] Function's args is empty\n");
		return false;
	}
	mcallargs_t& callArgs = callInfo->args;
	if (callArgs.size() != 2 && !qstrcmp(instruction->l.helper, "strcpy"))
	{
		error("[-] Number of strcpy function's args is incorrect\n");
		return false;
	}
	if (callArgs.size() != 3 && !qstrcmp(instruction->l.helper, "memcpy"))
	{
		error("[-] Number of memcpy function's args is incorrect\n");
		return false;
	}
	return true;
}

void utils::pushIntegerToVector(std::vector<unsigned char>& vec, unsigned long long input, const size_t length)
{
	for (size_t i = 0; i < length; i++)
	{
		vec.push_back((input >> (i * 8)) & 0xff);
	}
}

std::string utils::parseEscapedString(char* input)
{
	std::pair<const char, const char> const targetCharacters[]
	{
	  { 'a', 0x7 },
	  { 'b', 0x8 },
	  { 'f', 0xC },
	  { 'n', 0xA },
	  { 'r', 0xD },
	  { 't', 0x9 },
	  { 'v', 0xB },
	  { '"', 0x22},
	  {'\\', '\\'}
	};

	std::string parsedStr;
	for (size_t i = 1; i <= strlen(input); ++i)
	{
		parsedStr += input[i - 1];
		for (std::pair<const char, const char> const character : targetCharacters)
		{
			if (input[i] == character.first && input[i - 1] == '\\')
			{
				parsedStr[i - 1] = character.second;
				i += 1;
				break;
			}
		}
	}
	return parsedStr;
}

void utils::unescapeString(char* input, std::string& parsedRC4Key)
{
	for (size_t i = 0; i < strlen(input); i++)
	{
		if (input[i] == '\\' && input[i + 1] == '\\')
		{
			parsedRC4Key += "\\";
			i++;
			continue;
		}
		parsedRC4Key += input[i];
	}
}

bool utils::isPrintableAscii(unsigned char* string)
{
	for (int i = 0; string[i] != '\0'; i++)
	{
		bool isPrintableAscii = (string[i] & ~0x7f) == 0 && (isprint(string[i]) || isspace(string[i]));
		if (!isPrintableAscii)
			return false;
	}
	return true;
}

void utils::unpad(unsigned char* input, const size_t arrayLen)
{
	size_t lastElement = input[arrayLen - 1];
	if (lastElement > arrayLen)
	{
		return;
	}
	size_t stringLen = arrayLen - lastElement;
	std::memcpy(input, input, stringLen);
	input[stringLen] = '\0';
}

void utils::rc4_setup(struct rc4_state* s, unsigned char* key, int length)
{
	int i, j, k, * m, a;

	s->x = 0;
	s->y = 0;
	m = s->m;

	for (i = 0; i < 256; i++)
	{
		m[i] = i;
	}

	j = k = 0;

	for (i = 0; i < 256; i++)
	{
		a = m[i];
		j = (unsigned char)(j + a + key[k]);
		m[i] = m[j]; m[j] = a;
		if (++k >= length) k = 0;
	}
}

void utils::rc4_crypt(struct rc4_state* s, unsigned char* data, int length)
{
	int i, x, y, * m, a, b;

	x = s->x;
	y = s->y;
	m = s->m;

	for (i = 0; i < length; i++)
	{
		x = (unsigned char)(x + 1); a = m[x];
		y = (unsigned char)(y + a);
		m[x] = b = m[y];
		m[y] = a;
		data[i] ^= m[static_cast<unsigned char>(a + b)];
	}
	s->x = x;
	s->y = y;
}

unsigned char* utils::decryptAESCBC(const unsigned char* AESKey, const unsigned char* AESIV, const unsigned char* input, const size_t& inputLength)
{
	if (!inputLength || (inputLength % 16))
		return nullptr;
	AES aes(AESKeyLength::AES_256);
	unsigned char* decryptedString = aes.DecryptCBC(input, inputLength, AESKey, AESIV);
	unpad(decryptedString, inputLength);
	return decryptedString;
}

void utils::setDecompilerComment(cfunc_t& cfunc, unsigned long address, const std::string& decryptedString)
{
	treeloc_t ref_tree;
	ref_tree.ea = address;
	ref_tree.itp = ITP_SEMI;
	cfunc.set_user_cmt(ref_tree, decryptedString.c_str());
}