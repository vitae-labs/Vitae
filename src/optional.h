// Copyright (c) 2017-2019 The Bitcoin Core developers
// Copyright (c) 2020-2021 The Vitae Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VITAE_OPTIONAL_H
#define VITAE_OPTIONAL_H

#include <utility>

#include <boost/optional.hpp>

//! Substitute for C++17 std::optional
template <typename T>
using Optional = boost::optional<T>;

//! Substitute for C++17 std::make_optional
template <typename T>
Optional<T> MakeOptional(bool condition, T&& value)
{
    return boost::make_optional(condition, std::forward<T>(value));
}

//! Substitute for C++17 std::nullopt
static auto& nullopt = boost::none;

#endif // VITAE_OPTIONAL_H
