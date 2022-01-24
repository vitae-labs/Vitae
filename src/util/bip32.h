// Copyright (c) 2019 The Bitcoin Core developers
// Copyright (c) 2020-2021 The Vitae Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VITAE_UTIL_BIP32_H
#define VITAE_UTIL_BIP32_H

#include <attributes.h>
#include <string>
#include <vector>

/** Parse an HD keypaths like "m/7/0'/2000". */
NODISCARD bool ParseHDKeypath(const std::string& keypath_str, std::vector<uint32_t>& keypath);

/** Write HD keypaths as strings */
std::string WriteHDKeypath(const std::vector<uint32_t>& keypath);
std::string FormatHDKeypath(const std::vector<uint32_t>& path);

#endif // VITAE_UTIL_BIP32_H
