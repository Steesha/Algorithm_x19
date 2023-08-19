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
#include <Windows.h>
#include <cassert>

inline DWORD _asm_shld(DWORD p1, DWORD p2, BYTE cl)
{
	return (p2 >> (32 - cl)) | ((p1 & (0xFFFFFFFF >> cl)) << cl);
}

inline DWORD dword_add(DWORD a1, DWORD a2, BOOL& flag)
{
	flag = (((size_t)a1 + (size_t)a2) & 0xF00000000) != 0;
	return  a1 + a2;
}

inline void _numberProc(DWORD& eax, DWORD& ecx, DWORD& edx)
{
	//.BEGIN sub_2A355F0
	if ((ecx & 0xFF) >= 0x40)
	{
		eax = 0;
		edx = 0;
	}
	else
	{
		if ((ecx & 0xFF) >= 0x20)
		{
			edx = eax;
			eax = 0;

			//¸üÐÂcl
			DWORD temp1 = (ecx & 0xFF) & 0x1F;
			ecx &= 0xFFFFFF00;
			ecx |= temp1;
		}
		else
		{
			edx = _asm_shld(edx, eax, (ecx & 0xFF));
			eax <<= (ecx & 0xFF);
		}
	}
	//.END sub_2A355F0
}

std::string PeAuthSign::sign(const std::string& data)
{
	std::string un_encrypted = data;
	//²¹0
	while (un_encrypted.size() % 16)
	{
		un_encrypted += "0";
	}

	const size_t TABLE_SIZE = 0x200;
	const size_t ALGO_ROUND = 0x9;


	assert(un_encrypted.size() <= TABLE_SIZE);
	char* generatedTable = new char[TABLE_SIZE] {0};
	for (size_t i = 0; i < un_encrypted.size(); i += 4)
	{
		std::string temp1;
		temp1.assign(un_encrypted.begin() + i, un_encrypted.begin() + i + 4);
		temp1.assign(temp1.rbegin(), temp1.rend());
		size_t tableOffset;
		tableOffset = i * 2;
		assert(tableOffset <= TABLE_SIZE);
		memcpy_s(generatedTable + tableOffset, TABLE_SIZE - tableOffset, temp1.data(), temp1.size());
	}

	size_t paddingOffset = un_encrypted.size() * 2;
	size_t paddingSize = TABLE_SIZE - paddingOffset;
	PDWORD paddingAddr = (PDWORD)((size_t)generatedTable + paddingOffset);
	while ((size_t)paddingAddr < (size_t)generatedTable + TABLE_SIZE)
	{
		assert(paddingAddr != NULL);
		*paddingAddr = 0xABCDE987;
		paddingAddr += 2;
	}

	DWORD countFor = ALGO_ROUND;
	DWORD eax = 0, ebx = 0, ecx = 0, edx = 0xEFCDAB89, esi = 0, edi = 0;
	BOOL fl;

	DWORD ebp_0x30 = 0x40;
	DWORD ebp_0x38 = 0x98BADCFE;
	DWORD ebp_0x3c = 0x67452301;
	DWORD ebp_0x40 = 0xEFCDAB89;
	DWORD ebp_0x44 = 0;

	DWORD ebp_0x50 = 0;
	DWORD ebp_0x54 = 0;
	DWORD ebp_0x58 = 0;
	DWORD ebp_0x5c = 0x10325476;
	DWORD ebp_0x60 = 0;

	DWORD ebp_0x7c = 0x289B7EC6;
	DWORD ebp_0x80 = 3;
	DWORD ebp_0x84 = 0xEAA127FA;
	DWORD ebp_0x88 = 8;
	DWORD ebp_0x8C = 0xD4EF3085;
	DWORD ebp_0x90 = 0xB;
	DWORD ebp_0x94 = 0x04881D05;
	DWORD ebp_0x98 = 0x5;
	//DWORD ebp_0x9c = 0x17C40000;
	//counter

	while (true)
	{
		ebp_0x60 = 0;

		while (true)
		{
			ebx = *(PDWORD)(generatedTable + ebp_0x60 * 8);
			edi = edx;
			edx = ebp_0x44;
			edi = ~edi;
			edi &= ebp_0x5c;
			edx = ~edx;
			edx &= ebp_0x54;
			ecx = ebp_0x38;
			ecx &= ebp_0x40;
			eax = ebp_0x50;
			edi |= ecx;
			eax &= ebp_0x44;
			edx |= eax;
			edi = dword_add(edi, ebp_0x7c, fl);

			edx += fl;
			edi = dword_add(edi, ebx, fl);
			edx += *(PDWORD)(generatedTable + ebp_0x60 * 8 + 4) + fl;
			eax = ebp_0x3c;
			ecx = ebp_0x80;

			eax = dword_add(eax, edi, fl);
			edx += ebp_0x58 + fl;

			_numberProc(eax, ecx, edx);

			edi = ebp_0x5c;
			esi = eax;
			esi = dword_add(esi, ebp_0x40, fl);
			edi = ~edi;
			ecx = ebp_0x5c;
			edx += ebp_0x44 + fl;
			ecx &= ebp_0x40;
			edi &= ebp_0x38;
			edi |= ecx;
			eax &= ebp_0x44;
			ecx = ebp_0x60;
			ebp_0x58 = edx;
			edx = ebp_0x54;
			edx = ~edx;
			ebp_0x3c = esi;
			edx &= ebp_0x50;
			edx |= eax;
			edi = dword_add(edi, ebp_0x84, fl);

			edx += fl;
			edi = dword_add(edi, ebx, fl);
			edx += *(PDWORD)(generatedTable + ebp_0x60 * 8 + 4) + fl;

			edi = dword_add(edi, esi, fl);
			ecx = ebp_0x88;
			eax = edi;
			edx += ebp_0x58 + fl;

			_numberProc(eax, ecx, edx);

			ecx = ebp_0x40;
			edi = ebp_0x44;
			ecx = dword_add(ecx, eax, fl);
			eax = ebp_0x5c;
			esi = ebp_0x60;
			edi += edx + fl;
			eax ^= ebp_0x38;
			edx = ebp_0x54;
			eax ^= ecx;
			edx ^= ebp_0x50;
			edx ^= edi;
			ebp_0x40 = ecx;
			eax = dword_add(eax, ebp_0x8C, fl);

			edx += fl;
			ebp_0x44 = edi;
			eax = dword_add(eax, ebx, fl);
			edi = *(PDWORD)(generatedTable + esi * 8 + 4);
			edx += edi + fl;
			eax = dword_add(eax, ebp_0x3c, fl);
			ecx = ebp_0x90;
			edx += ebp_0x58 + fl;

			_numberProc(eax, ecx, edx);

			eax = dword_add(eax, ebp_0x40, fl);
			ebp_0x50 = edx;
			edx = ebp_0x44;
			ebp_0x50 += edx + fl;
			ebp_0x38 = eax;
			edx |= ebp_0x54;
			edx ^= ebp_0x50;
			eax = dword_add((ebp_0x5c | ebp_0x40) ^ ebp_0x38, ebp_0x94, fl);
			ecx = ebp_0x98;
			edx += fl;
			eax = dword_add(eax, ebx, fl);
			edx += edi + fl;
			eax = dword_add(eax, ebp_0x3c, fl);
			edx += ebp_0x58;

			_numberProc(eax, ecx, edx);

			ebx = eax;
			ebx = dword_add(ebx, ebp_0x40, fl);
			eax = esi;
			esi = ebp_0x30;

			edx += ebp_0x44 + fl;
			eax += 4;
			ebp_0x54 = edx;
			edx = ebp_0x40;
			ebp_0x5c = ebx;
			ebp_0x60 = eax;
			if (eax >= esi) break;
		}
		countFor--;
		if (countFor == 0) break;
	}

	char* result = new char[16];
	memcpy_s(result + 4 * 0, sizeof(DWORD), &ebp_0x3c, sizeof(DWORD));
	memcpy_s(result + 4 * 1, sizeof(DWORD), &ebp_0x40, sizeof(DWORD));
	memcpy_s(result + 4 * 2, sizeof(DWORD), &ebp_0x38, sizeof(DWORD));
	memcpy_s(result + 4 * 3, sizeof(DWORD), &ebp_0x5c, sizeof(DWORD));
	std::string sResult = Base64::base64_encode((std::uint8_t const*)result, 16);

	delete[] generatedTable;
	delete[] result;
	return sResult;
}
