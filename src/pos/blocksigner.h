// Copyright (c) 2020 The Bitcones developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BLOCKSIGNER_H
#define BLOCKSIGNER_H

#include <primitives/block.h>
#include <primitives/transaction.h>
#include <wallet/wallet.h>

bool SignBlockWithKey(CBlock& block, const CKey& key);
bool SignBlock(CBlock& block, const CWallet& keystore);
bool CheckBlockSignature(const CBlock& block);

#endif // BLOCKSIGNER_H
