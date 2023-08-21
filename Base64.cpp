#include "Base64.h"

std::size_t encode(void* dest, const void* src, std::size_t len) {
	char* out = static_cast<char*>(dest);
	char const* in = static_cast<char const*>(src);
	char constexpr tab[] = { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" };
	for (auto n = len / 3; n--;) {
		*out++ = tab[(in[0] & 0xfc) >> 2];
		*out++ = tab[((in[0] & 0x03) << 4) + ((in[1] & 0xf0) >> 4)];
		*out++ = tab[((in[2] & 0xc0) >> 6) + ((in[1] & 0x0f) << 2)];
		*out++ = tab[in[2] & 0x3f];
		in += 3;
	}

	switch (len % 3) {
	case 2:
		*out++ = tab[(in[0] & 0xfc) >> 2];
		*out++ = tab[((in[0] & 0x03) << 4) + ((in[1] & 0xf0) >> 4)];
		*out++ = tab[(in[1] & 0x0f) << 2];
		*out++ = '=';
		break;
	case 1:
		*out++ = tab[(in[0] & 0xfc) >> 2];
		*out++ = tab[((in[0] & 0x03) << 4)];
		*out++ = '=';
		*out++ = '=';
		break;
	case 0:
		break;
	}

	return out - static_cast<char*>(dest);
}

std::string base64_encode(std::uint8_t const* data, std::size_t len)
{
	std::string dest;
	dest.resize(4 * ((len + 2) / 3));
	dest.resize(encode(&dest[0], data, len));
	return dest;
}
