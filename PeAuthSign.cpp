/*
	Algorithm_x19 to make a third party WPFLauncher.
	Copyright (C) 2023  Steesha

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include "PeAuthSign.h"
#include "Base64.h"
#include <stdexcept>

#define offs(p1,p2,bits) p1 = (p2 >> (32 - bits)) | ((p1 & (0xFFFFFFFF >> bits)) << bits); p2 <<= bits;
#define DWORD unsigned long

const size_t TABLE_SIZE = 64 * sizeof(DWORD);
std::string sign(const std::string& data)
{
	std::string un_encrypted = data;
	//ฒน0
	while (un_encrypted.size() % 4)
	{
		un_encrypted += "0";
	}

	size_t groups = un_encrypted.size() / 4;
	if (un_encrypted.size() > TABLE_SIZE)
	{
		throw std::length_error("data too big");
	}

	DWORD cryptoTable[64] = { 0 };
	for (size_t i = 0; i < 64; i++)
	{
		cryptoTable[i] = 0xABCDE987;
	}

	for (size_t i = 0; i < groups; i++)
	{
		std::string rev;
		auto iBegin = un_encrypted.begin() + i * 4;
		rev.assign(iBegin, iBegin + 4);
		rev.assign(rev.rbegin(), rev.rend());
		memcpy_s(cryptoTable + i, sizeof(cryptoTable[i]), rev.data(), rev.size());
	}

	DWORD L1[] = { 0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05 };
	DWORD L2[] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 };
	DWORD L3[] = { 0, 0, 0, 0 };
	DWORD L4[] = { 0, 0, 0, 0 };

	for (size_t i = 0; i < 9; i++)
	{
		for (size_t j = 0; j < 16; j++)
		{
			L4[3] = cryptoTable[j * 4];

			L4[0] = L1[0] + L2[0] + L4[3] + (~L2[1] & L2[3] | L2[2] & L2[1]);
			L4[1] = (L4[1] | L3[1] & L3[0]) + L3[3];
			offs(L4[1], L4[0], 3);

			L2[0] = L4[0] + L2[1];
			L3[3] = L4[1] + L3[0];
			L4[1] = (~L3[2] & L3[1]) | (L4[0] & L3[0]);
			L4[2] = (~L2[3] & L2[2] | L2[3] & L2[1]) + L1[1] + L4[3] + L2[0];
			L4[0] = L4[2];
			L4[1] += L3[3];
			offs(L4[1], L4[0], 8);

			L2[1] += L4[0];
			L4[1] = (L3[1] ^ L3[2] ^ (L3[0] + L4[1])) + L3[3];
			L4[0] = (L2[1] ^ L2[2] ^ L2[3]) + L1[2] + L2[0] + L4[3];
			L3[0] = L4[2];
			offs(L4[1], L4[0], 11);

			L3[1] = L4[1] + L3[0];
			L2[2] = L4[0] + L2[1];
			L4[1] = ((L3[0] | L3[2]) ^ L3[1]) + L4[2] + L3[3];
			L4[0] = ((L2[3] | L2[1]) ^ L2[2]) + L1[3] + L4[3] + L2[0];
			offs(L4[1], L4[0], 5);

			L2[3] = L4[0] + L2[1];
			L3[2] = L4[1] + L3[0];
		}
	}

	std::string sResult = base64_encode((std::uint8_t const*)L2, sizeof(L2));
	return sResult;
}