// Copyright (c) 2014-2019 The Bitcoin Core developers
// Copyright (c) 2020-2021 The Vitae Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VITAE_ZMQ_ZMQCONFIG_H
#define VITAE_ZMQ_ZMQCONFIG_H

#if defined(HAVE_CONFIG_H)
#include <config/vitae-config.h>
#endif

#include <stdarg.h>

#if ENABLE_ZMQ
#include <zmq.h>
#endif

#include <primitives/transaction.h>

void zmqError(const char *str);

#endif // VITAE_ZMQ_ZMQCONFIG_H
