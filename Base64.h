// src from: https://www.boost.org/doc/libs/1_66_0/boost/beast/core/detail/base64.hpp
#pragma once
#include <string>

std::string base64_encode(std::uint8_t const* data, std::size_t len);