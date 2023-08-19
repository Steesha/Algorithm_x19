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

#include <iostream>
#include "PeAuthSign.h"
int main()
{
	//PeAuthSign ��netease pe�˵�¼����/pe-authentication�е�sign�㷨
	//ʹ�÷��������� message�ֶε�����
	//message �ֶ����û��޹أ������һ��uuid����ͬ�����е�seed
	//message �ֶ�ǰ��������й���MC��У�飬����.so�ļ���У�飬�汾�ŵȵ��д���������̽��
	std::string dataIn = 
		"2.7.5.227892c53528dbe41c07311c3a123e70ba37fd2.7.18.229723082410acd"
		"8f646b9354cbb04e9c41a4d2b3e7ca013bb30a74d822579860c042bfadcb57c-34"
		"52-4ea8-aaa2-cd7f2791a3f3";

	std::unique_ptr<PeAuthSign> sign(new PeAuthSign());
	std::string dataOut = sign->sign(dataIn);
	std::cout << "[sign result]" << dataOut << "\n";

	system("pause");
	return 0;
}
