// Copyright (c) 2020 The Bitcones developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pos/blocksigner.h>
#include <script/signingprovider.h>
#include <primitives/block.h>
#include <util/system.h>
#include <util/strencodings.h>

typedef std::vector<unsigned char> valtype;
bool SignBlock(CBlock& block, const CWallet& keystore)
{
    std::vector<valtype> vSolutions;
    const CTxOut& txout = block.vtx[1]->vout[1];

    txnouttype which_type = Solver(txout.scriptPubKey, vSolutions);

    if ( which_type != txnouttype::TX_PUBKEY && which_type != TX_PUBKEYHASH) {

        return false;
    }

    const valtype& vchPubKey = vSolutions[0];

    CKey key;
    if (!keystore.GetLegacyScriptPubKeyMan()->GetKey( which_type == TX_PUBKEY ? CPubKey(vchPubKey).GetID() :
                                                         CKeyID(uint160(vchPubKey)), key)) {

        return false;
    }

    return key.Sign(block.GetHash(), block.vchBlockSig, 0);
}

bool CheckBlockSignature(const CBlock& block)
{
    std::vector<valtype> vSolutions;

    if (block.IsProofOfWork())
        return block.vchBlockSig.empty();

    if (block.vchBlockSig.empty())
        return error("%s: vchBlockSig is empty!", __func__);

    CPubKey pubkey;
    const CTxOut& txout = block.vtx[1]->vout[1];
    txnouttype whichType = Solver(txout.scriptPubKey, vSolutions);
    if (!whichType)
        return false;
    if (whichType == TX_PUBKEY || whichType == TX_PUBKEYHASH) {
        valtype& vchPubKey = vSolutions[0];
        pubkey = CPubKey(vchPubKey);
    }

    if (!pubkey.IsValid())
        return error("%s: invalid pubkey %s", __func__, HexStr(pubkey));

    return pubkey.Verify(block.GetHash(), block.vchBlockSig);
}
