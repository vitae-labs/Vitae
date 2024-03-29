// Copyright (c) 2019 The Bitcoin Core developers
// Copyright (c) 2020-2021 The Vitae Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VITAE_TEST_UTIL_LOGGING_H
#define VITAE_TEST_UTIL_LOGGING_H

#include <util/macros.h>

#include <functional>
#include <list>
#include <string>

class DebugLogHelper
{
    const std::string m_message;
    bool m_found{false};
    std::list<std::function<void(const std::string&)>>::iterator m_print_connection;

    void check_found();

public:
    DebugLogHelper(std::string message);
    ~DebugLogHelper() { check_found(); }
};

#define ASSERT_DEBUG_LOG(message) DebugLogHelper PASTE2(debugloghelper, __COUNTER__)(message)

#endif // VITAE_TEST_UTIL_LOGGING_H
