// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Copyright (c) 2020-2021 The Vitae Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <amount.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/consensus.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <key_io.h>
#include <miner.h>
#include <net.h>
#include <node/context.h>
#include <policy/fees.h>
#include <pow.h>
#include <rpc/blockchain.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <shutdown.h>
#include <txmempool.h>
#include <univalue.h>
#include <util/fees.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/system.h>
#include <validation.h>
#include <validationinterface.h>
#include <versionbitsinfo.h>
#include <warnings.h>

#include <masternodes/activemasternode.h>
#include <masternodes/masternodeman.h>
#include <masternodes/masternodeconfig.h>
#include <wallet/rpcwallet.h>

#include <boost/lexical_cast.hpp>
#include <iomanip>

#include <memory>
#include <stdint.h>

/**
 * Return average network hashes per second based on the last 'lookup' blocks,
 * or from the last difficulty change if 'lookup' is nonpositive.
 * If 'height' is nonnegative, compute the estimate at the time when a given block was found.
 */
static UniValue GetNetworkHashPS(int lookup, int height) {
    CBlockIndex *pb = ::ChainActive().Tip();

    if (height >= 0 && height < ::ChainActive().Height())
        pb = ::ChainActive()[height];

    if (pb == nullptr || !pb->nHeight)
        return 0;

    // If lookup is -1, then use blocks since last difficulty change.
    if (lookup <= 0)
        lookup = pb->nHeight % Params().GetConsensus().DifficultyAdjustmentInterval() + 1;

    // If lookup is larger than chain, then set it to chain length.
    if (lookup > pb->nHeight)
        lookup = pb->nHeight;

    CBlockIndex *pb0 = pb;
    int64_t minTime = pb0->GetBlockTime();
    int64_t maxTime = minTime;
    for (int i = 0; i < lookup; i++) {
        pb0 = pb0->pprev;
        int64_t time = pb0->GetBlockTime();
        minTime = std::min(time, minTime);
        maxTime = std::max(time, maxTime);
    }

    // In case there's a situation where minTime == maxTime, we don't want a divide by zero exception.
    if (minTime == maxTime)
        return 0;

    arith_uint256 workDiff = pb->nChainWork - pb0->nChainWork;
    int64_t timeDiff = maxTime - minTime;

    return workDiff.getdouble() / timeDiff;
}

static UniValue getnetworkhashps(const JSONRPCRequest& request)
{
            RPCHelpMan{"getnetworkhashps",
                "\nReturns the estimated network hashes per second based on the last n blocks.\n"
                "Pass in [blocks] to override # of blocks, -1 specifies since last difficulty change.\n"
                "Pass in [height] to estimate the network speed at the time when a certain block was found.\n",
                {
                    {"nblocks", RPCArg::Type::NUM, /* default */ "120", "The number of blocks, or -1 for blocks since last difficulty change."},
                    {"height", RPCArg::Type::NUM, /* default */ "-1", "To estimate at the time of the given height."},
                },
                RPCResult{
                    RPCResult::Type::NUM, "", "Hashes per second estimated"},
                RPCExamples{
                    HelpExampleCli("getnetworkhashps", "")
            + HelpExampleRpc("getnetworkhashps", "")
                },
            }.Check(request);

    LOCK(cs_main);
    return GetNetworkHashPS(!request.params[0].isNull() ? request.params[0].get_int() : 120, !request.params[1].isNull() ? request.params[1].get_int() : -1);
}

static UniValue generateBlocks(const CTxMemPool& mempool, const CScript& coinbase_script, int nGenerate, uint64_t nMaxTries)
{
    int nHeightEnd = 0;
    int nHeight = 0;

    {   // Don't keep cs_main locked
        LOCK(cs_main);
        nHeight = ::ChainActive().Height();
        nHeightEnd = nHeight+nGenerate;
    }
    unsigned int nExtraNonce = 0;
    UniValue blockHashes(UniValue::VARR);
    while (true)
    {
        std::unique_ptr<CBlockTemplate> pblocktemplate(BlockAssembler(mempool, Params()).CreateNewBlock(coinbase_script));
        if (!pblocktemplate.get())
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't create new block");
        CBlock *pblock = &pblocktemplate->block;
        {
            LOCK(cs_main);
            IncrementExtraNonce(pblock, ::ChainActive().Tip(), nExtraNonce);
        }
        while (nMaxTries > 0 && pblock->nNonce < std::numeric_limits<uint32_t>::max() && !CheckProofOfWork(pblock->GetHash(), pblock->nBits, Params().GetConsensus()) && !ShutdownRequested()) {
            ++pblock->nNonce;
            --nMaxTries;
        }
        if (pblock->nNonce == std::numeric_limits<uint32_t>::max()) {
            continue;
        }
        std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(*pblock);
        if (!ProcessNewBlock(Params(), shared_pblock, true, nullptr))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "ProcessNewBlock, block not accepted");
        ++nHeight;
        blockHashes.push_back(pblock->GetHash().GetHex());
    }
    return blockHashes;
}

static UniValue generatetodescriptor(const JSONRPCRequest& request)
{
    RPCHelpMan{
        "generatetodescriptor",
        "\nMine blocks immediately to a specified descriptor (before the RPC call returns)\n",
        {
            {"num_blocks", RPCArg::Type::NUM, RPCArg::Optional::NO, "How many blocks are generated immediately."},
            {"descriptor", RPCArg::Type::STR, RPCArg::Optional::NO, "The descriptor to send the newly generated vitae to."},
            {"maxtries", RPCArg::Type::NUM, /* default */ "1000000", "How many iterations to try."},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "hashes of blocks generated",
            {
                {RPCResult::Type::STR_HEX, "", "blockhash"},
            }
        },
        RPCExamples{
            "\nGenerate 11 blocks to mydesc\n" + HelpExampleCli("generatetodescriptor", "11 \"mydesc\"")},
    }
        .Check(request);

    const int num_blocks{request.params[0].get_int()};
    const int64_t max_tries{request.params[2].isNull() ? 1000000 : request.params[2].get_int()};

    FlatSigningProvider key_provider;
    std::string error;
    const auto desc = Parse(request.params[1].get_str(), key_provider, error, /* require_checksum = */ false);
    if (!desc) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error);
    }
    if (desc->IsRange()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Ranged descriptor not accepted. Maybe pass through deriveaddresses first?");
    }

    FlatSigningProvider provider;
    std::vector<CScript> coinbase_script;
    if (!desc->Expand(0, key_provider, coinbase_script, provider)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Cannot derive script without private keys"));
    }

    const CTxMemPool& mempool = EnsureMemPool();

    CHECK_NONFATAL(coinbase_script.size() == 1);

    return generateBlocks(mempool, coinbase_script.at(0), num_blocks, max_tries);
}

static UniValue generatetoaddress(const JSONRPCRequest& request)
{
            RPCHelpMan{"generatetoaddress",
                "\nMine blocks immediately to a specified address (before the RPC call returns)\n",
                {
                    {"nblocks", RPCArg::Type::NUM, RPCArg::Optional::NO, "How many blocks are generated immediately."},
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The address to send the newly generated vitae to."},
                    {"maxtries", RPCArg::Type::NUM, /* default */ "1000000", "How many iterations to try."},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "hashes of blocks generated",
                    {
                        {RPCResult::Type::STR_HEX, "", "blockhash"},
                    }},
                RPCExamples{
            "\nGenerate 11 blocks to myaddress\n"
            + HelpExampleCli("generatetoaddress", "11 \"myaddress\"")
            + "If you are running the vitae core wallet, you can get a new address to send the newly generated vitae to with:\n"
            + HelpExampleCli("getnewaddress", "")
                },
            }.Check(request);

    int nGenerate = request.params[0].get_int();
    uint64_t nMaxTries = 1000000;
    if (!request.params[2].isNull()) {
        nMaxTries = request.params[2].get_int();
    }

    CTxDestination destination = DecodeDestination(request.params[1].get_str());
    if (!IsValidDestination(destination)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address");
    }

    const CTxMemPool& mempool = EnsureMemPool();

    CScript coinbase_script = GetScriptForDestination(destination);

    return generateBlocks(mempool, coinbase_script, nGenerate, nMaxTries);
}

static UniValue getmininginfo(const JSONRPCRequest& request)
{
            RPCHelpMan{"getmininginfo",
                "\nReturns a json object containing mining-related information.",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "blocks", "The current block"},
                        {RPCResult::Type::NUM, "currentblockweight", /* optional */ true, "The block weight of the last assembled block (only present if a block was ever assembled)"},
                        {RPCResult::Type::NUM, "currentblocktx", /* optional */ true, "The number of block transactions of the last assembled block (only present if a block was ever assembled)"},
                        {RPCResult::Type::NUM, "difficulty", "The current difficulty"},
                        {RPCResult::Type::NUM, "networkhashps", "The network hashes per second"},
                        {RPCResult::Type::NUM, "pooledtx", "The size of the mempool"},
                        {RPCResult::Type::STR, "chain", "current network name (main, test, regtest)"},
                        {RPCResult::Type::STR, "warnings", "any network and blockchain warnings"},
                    }},
                RPCExamples{
                    HelpExampleCli("getmininginfo", "")
            + HelpExampleRpc("getmininginfo", "")
                },
            }.Check(request);

    LOCK(cs_main);
    const CTxMemPool& mempool = EnsureMemPool();

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("blocks",           (int)::ChainActive().Height());
    if (BlockAssembler::m_last_block_weight) obj.pushKV("currentblockweight", *BlockAssembler::m_last_block_weight);
    if (BlockAssembler::m_last_block_num_txs) obj.pushKV("currentblocktx", *BlockAssembler::m_last_block_num_txs);
    obj.pushKV("difficulty",       (double)GetDifficulty(::ChainActive().Tip()));
    obj.pushKV("networkhashps",    getnetworkhashps(request));
    obj.pushKV("pooledtx",         (uint64_t)mempool.size());
    obj.pushKV("chain",            Params().NetworkIDString());
    obj.pushKV("warnings",         GetWarnings(false));
    return obj;
}


// NOTE: Unlike wallet RPC (which use VITAE values), mining RPCs follow GBT (BIP 22) in using satoshi amounts
static UniValue prioritisetransaction(const JSONRPCRequest& request)
{
            RPCHelpMan{"prioritisetransaction",
                "Accepts the transaction into mined blocks at a higher (or lower) priority\n",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id."},
                    {"dummy", RPCArg::Type::NUM, RPCArg::Optional::OMITTED_NAMED_ARG, "API-Compatibility for previous API. Must be zero or null.\n"
            "                  DEPRECATED. For forward compatibility use named arguments and omit this parameter."},
                    {"fee_delta", RPCArg::Type::NUM, RPCArg::Optional::NO, "The fee value (in satoshis) to add (or subtract, if negative).\n"
            "                  Note, that this value is not a fee rate. It is a value to modify absolute fee of the TX.\n"
            "                  The fee is not actually paid, only the algorithm for selecting transactions into a block\n"
            "                  considers the transaction as it would have paid a higher (or lower) fee."},
                },
                RPCResult{
                    RPCResult::Type::BOOL, "", "Returns true"},
                RPCExamples{
                    HelpExampleCli("prioritisetransaction", "\"txid\" 0.0 10000")
            + HelpExampleRpc("prioritisetransaction", "\"txid\", 0.0, 10000")
                },
            }.Check(request);

    LOCK(cs_main);

    uint256 hash(ParseHashV(request.params[0], "txid"));
    CAmount nAmount = request.params[2].get_int64();

    if (!(request.params[1].isNull() || request.params[1].get_real() == 0)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Priority is no longer supported, dummy argument to prioritisetransaction must be 0.");
    }

    EnsureMemPool().PrioritiseTransaction(hash, nAmount);
    return true;
}


// NOTE: Assumes a conclusive result; if result is inconclusive, it must be handled by caller
static UniValue BIP22ValidationResult(const BlockValidationState& state)
{
    if (state.IsValid())
        return NullUniValue;

    if (state.IsError())
        throw JSONRPCError(RPC_VERIFY_ERROR, state.ToString());
    if (state.IsInvalid())
    {
        std::string strRejectReason = state.GetRejectReason();
        if (strRejectReason.empty())
            return "rejected";
        return strRejectReason;
    }
    // Should be impossible
    return "valid?";
}

static std::string gbt_vb_name(const Consensus::DeploymentPos pos) {
    const struct VBDeploymentInfo& vbinfo = VersionBitsDeploymentInfo[pos];
    std::string s = vbinfo.name;
    if (!vbinfo.gbt_force) {
        s.insert(s.begin(), '!');
    }
    return s;
}

static UniValue getblocktemplate(const JSONRPCRequest& request)
{
            RPCHelpMan{"getblocktemplate",
                "\nIf the request parameters include a 'mode' key, that is used to explicitly select between the default 'template' request or a 'proposal'.\n"
                "It returns data needed to construct a block to work on.\n"
                "For full specification, see BIPs 22, 23, 9, and 145:\n"
                "    https://github.com/vitae/bips/blob/master/bip-0022.mediawiki\n"
                "    https://github.com/vitae/bips/blob/master/bip-0023.mediawiki\n"
                "    https://github.com/vitae/bips/blob/master/bip-0009.mediawiki#getblocktemplate_changes\n"
                "    https://github.com/vitae/bips/blob/master/bip-0145.mediawiki\n",
                {
                    {"template_request", RPCArg::Type::OBJ, "{}", "Format of the template",
                        {
                            {"mode", RPCArg::Type::STR, /* treat as named arg */ RPCArg::Optional::OMITTED_NAMED_ARG, "This must be set to \"template\", \"proposal\" (see BIP 23), or omitted"},
                            {"capabilities", RPCArg::Type::ARR, /* treat as named arg */ RPCArg::Optional::OMITTED_NAMED_ARG, "A list of strings",
                                {
                                    {"support", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "client side supported feature, 'longpoll', 'coinbasetxn', 'coinbasevalue', 'proposal', 'serverlist', 'workid'"},
                                },
                                },
                            {"rules", RPCArg::Type::ARR, RPCArg::Optional::NO, "A list of strings",
                                {
                                    {"support", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "client side supported softfork deployment"},
                                },
                                },
                        },
                        "\"template_request\""},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "version", "The preferred block version"},
                        {RPCResult::Type::ARR, "rules", "specific block rules that are to be enforced",
                            {
                                {RPCResult::Type::STR, "", "rulename"},
                            }},
                        {RPCResult::Type::OBJ_DYN, "vbavailable", "set of pending, supported versionbit (BIP 9) softfork deployments",
                            {
                                {RPCResult::Type::NUM, "rulename", "identifies the bit number as indicating acceptance and readiness for the named softfork rule"},
                            }},
                        {RPCResult::Type::NUM, "vbrequired", "bit mask of versionbits the server requires set in submissions"},
                        {RPCResult::Type::STR, "previousblockhash", "The hash of current highest block"},
                        {RPCResult::Type::ARR, "", "contents of non-coinbase transactions that should be included in the next block",
                            {
                                {RPCResult::Type::OBJ, "", "",
                                    {
                                        {RPCResult::Type::STR_HEX, "data", "transaction data encoded in hexadecimal (byte-for-byte)"},
                                        {RPCResult::Type::STR_HEX, "txid", "transaction id encoded in little-endian hexadecimal"},
                                        {RPCResult::Type::STR_HEX, "hash", "hash encoded in little-endian hexadecimal (including witness data)"},
                                        {RPCResult::Type::ARR, "depends", "array of numbers",
                                            {
                                                {RPCResult::Type::NUM, "", "transactions before this one (by 1-based index in 'transactions' list) that must be present in the final block if this one is"},
                                            }},
                                        {RPCResult::Type::NUM, "fee", "difference in value between transaction inputs and outputs (in satoshis); for coinbase transactions, this is a negative Number of the total collected block fees (ie, not including the block subsidy); if key is not present, fee is unknown and clients MUST NOT assume there isn't one"},
                                        {RPCResult::Type::NUM, "sigops", "total SigOps cost, as counted for purposes of block limits; if key is not present, sigop cost is unknown and clients MUST NOT assume it is zero"},
                                        {RPCResult::Type::NUM, "weight", "total transaction weight, as counted for purposes of block limits"},
                                    }},
                            }},
                        {RPCResult::Type::OBJ, "coinbaseaux", "data that should be included in the coinbase's scriptSig content",
                        {
                            {RPCResult::Type::ELISION, "", ""},
                        }},
                        {RPCResult::Type::NUM, "coinbasevalue", "maximum allowable input to coinbase transaction, including the generation award and transaction fees (in satoshis)"},
                        {RPCResult::Type::OBJ, "coinbasetxn", "information for coinbase transaction",
                        {
                            {RPCResult::Type::ELISION, "", ""},
                        }},
                        {RPCResult::Type::STR, "target", "The hash target"},
                        {RPCResult::Type::NUM_TIME, "mintime", "The minimum timestamp appropriate for the next block time, expressed in " + UNIX_EPOCH_TIME},
                        {RPCResult::Type::ARR, "mutable", "list of ways the block template may be changed",
                            {
                                {RPCResult::Type::STR, "value", "A way the block template may be changed, e.g. 'time', 'transactions', 'prevblock'"},
                            }},
                        {RPCResult::Type::STR_HEX, "noncerange", "A range of valid nonces"},
                        {RPCResult::Type::NUM, "sigoplimit", "limit of sigops in blocks"},
                        {RPCResult::Type::NUM, "sizelimit", "limit of block size"},
                        {RPCResult::Type::NUM, "weightlimit", "limit of block weight"},
                        {RPCResult::Type::NUM_TIME, "curtime", "current timestamp in " + UNIX_EPOCH_TIME},
                        {RPCResult::Type::STR, "bits", "compressed target of next block"},
                        {RPCResult::Type::NUM, "height", "The height of the next block"},
                    }},
                RPCExamples{
                    HelpExampleCli("getblocktemplate", "'{\"rules\": [\"segwit\"]}'")
            + HelpExampleRpc("getblocktemplate", "{\"rules\": [\"segwit\"]}")
                },
            }.Check(request);

    LOCK(cs_main);

    std::string strMode = "template";
    UniValue lpval = NullUniValue;
    std::set<std::string> setClientRules;
    int64_t nMaxVersionPreVB = -1;
    if (!request.params[0].isNull())
    {
        const UniValue& oparam = request.params[0].get_obj();
        const UniValue& modeval = find_value(oparam, "mode");
        if (modeval.isStr())
            strMode = modeval.get_str();
        else if (modeval.isNull())
        {
            /* Do nothing */
        }
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
        lpval = find_value(oparam, "longpollid");

        if (strMode == "proposal")
        {
            const UniValue& dataval = find_value(oparam, "data");
            if (!dataval.isStr())
                throw JSONRPCError(RPC_TYPE_ERROR, "Missing data String key for proposal");

            CBlock block;
            if (!DecodeHexBlk(block, dataval.get_str()))
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

            uint256 hash = block.GetHash();
            const CBlockIndex* pindex = LookupBlockIndex(hash);
            if (pindex) {
                if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
                    return "duplicate";
                if (pindex->nStatus & BLOCK_FAILED_MASK)
                    return "duplicate-invalid";
                return "duplicate-inconclusive";
            }

            CBlockIndex* const pindexPrev = ::ChainActive().Tip();
            // TestBlockValidity only supports blocks built on the current Tip
            if (block.hashPrevBlock != pindexPrev->GetBlockHash())
                return "inconclusive-not-best-prevblk";
            BlockValidationState state;
            TestBlockValidity(state, Params(), block, pindexPrev, false, true);
            return BIP22ValidationResult(state);
        }

        const UniValue& aClientRules = find_value(oparam, "rules");
        if (aClientRules.isArray()) {
            for (unsigned int i = 0; i < aClientRules.size(); ++i) {
                const UniValue& v = aClientRules[i];
                setClientRules.insert(v.get_str());
            }
        } else {
            // NOTE: It is important that this NOT be read if versionbits is supported
            const UniValue& uvMaxVersion = find_value(oparam, "maxversion");
            if (uvMaxVersion.isNum()) {
                nMaxVersionPreVB = uvMaxVersion.get_int64();
            }
        }
    }

    if (strMode != "template")
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");

    if(!g_rpc_node->connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    if (g_rpc_node->connman->GetNodeCount(CConnman::CONNECTIONS_ALL) == 0)
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, PACKAGE_NAME " is not connected!");

    if (::ChainstateActive().IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, PACKAGE_NAME " is in initial sync and waiting for blocks...");

    static unsigned int nTransactionsUpdatedLast;
    const CTxMemPool& mempool = EnsureMemPool();

    if (!lpval.isNull())
    {
        // Wait to respond until either the best block changes, OR a minute has passed and there are more transactions
        uint256 hashWatchedChain;
        std::chrono::steady_clock::time_point checktxtime;
        unsigned int nTransactionsUpdatedLastLP;

        if (lpval.isStr())
        {
            // Format: <hashBestChain><nTransactionsUpdatedLast>
            std::string lpstr = lpval.get_str();

            hashWatchedChain = ParseHashV(lpstr.substr(0, 64), "longpollid");
            nTransactionsUpdatedLastLP = atoi64(lpstr.substr(64));
        }
        else
        {
            // NOTE: Spec does not specify behaviour for non-string longpollid, but this makes testing easier
            hashWatchedChain = ::ChainActive().Tip()->GetBlockHash();
            nTransactionsUpdatedLastLP = nTransactionsUpdatedLast;
        }

        // Release lock while waiting
        LEAVE_CRITICAL_SECTION(cs_main);
        {
            checktxtime = std::chrono::steady_clock::now() + std::chrono::minutes(1);

            WAIT_LOCK(g_best_block_mutex, lock);
            while (g_best_block == hashWatchedChain && IsRPCRunning())
            {
                if (g_best_block_cv.wait_until(lock, checktxtime) == std::cv_status::timeout)
                {
                    // Timeout: Check transactions for update
                    // without holding the mempool lock to avoid deadlocks
                    if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLastLP)
                        break;
                    checktxtime += std::chrono::seconds(10);
                }
            }
        }
        ENTER_CRITICAL_SECTION(cs_main);

        if (!IsRPCRunning())
            throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Shutting down");
        // TODO: Maybe recheck connections/IBD and (if something wrong) send an expires-immediately template to stop miners?
    }

    // GBT must be called with 'segwit' set in the rules
    if (setClientRules.count("segwit") != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "getblocktemplate must be called with the segwit rule set (call with {\"rules\": [\"segwit\"]})");
    }

    // Update block
    static CBlockIndex* pindexPrev;
    static int64_t nStart;
    static std::unique_ptr<CBlockTemplate> pblocktemplate;
    if (pindexPrev != ::ChainActive().Tip() ||
        (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 5))
    {
        // Clear pindexPrev so future calls make a new block, despite any failures from here on
        pindexPrev = nullptr;

        // Store the pindexBest used before CreateNewBlock, to avoid races
        nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
        CBlockIndex* pindexPrevNew = ::ChainActive().Tip();
        nStart = GetTime();

        // Create new block
        CScript scriptDummy = CScript() << OP_TRUE;
        pblocktemplate = BlockAssembler(mempool, Params()).CreateNewBlock(scriptDummy);
        if (!pblocktemplate)
            throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");

        // Need to update only after we know CreateNewBlock succeeded
        pindexPrev = pindexPrevNew;
    }
    CHECK_NONFATAL(pindexPrev);
    CBlock* pblock = &pblocktemplate->block; // pointer for convenience
    const Consensus::Params& consensusParams = Params().GetConsensus();

    // Update nTime
    UpdateTime(pblock, consensusParams, pindexPrev);
    pblock->nNonce = 0;

    // NOTE: If at some point we support pre-segwit miners post-segwit-activation, this needs to take segwit support into consideration
    const bool fPreSegWit = (pindexPrev->nHeight + 1 < consensusParams.SegwitHeight);

    UniValue aCaps(UniValue::VARR); aCaps.push_back("proposal");

    UniValue transactions(UniValue::VARR);
    std::map<uint256, int64_t> setTxIndex;
    int i = 0;
    for (const auto& it : pblock->vtx) {
        const CTransaction& tx = *it;
        uint256 txHash = tx.GetHash();
        setTxIndex[txHash] = i++;

        if (tx.IsCoinBase())
            continue;

        UniValue entry(UniValue::VOBJ);

        entry.pushKV("data", EncodeHexTx(tx));
        entry.pushKV("txid", txHash.GetHex());
        entry.pushKV("hash", tx.GetWitnessHash().GetHex());

        UniValue deps(UniValue::VARR);
        for (const CTxIn &in : tx.vin)
        {
            if (setTxIndex.count(in.prevout.hash))
                deps.push_back(setTxIndex[in.prevout.hash]);
        }
        entry.pushKV("depends", deps);

        int index_in_template = i - 1;
        entry.pushKV("fee", pblocktemplate->vTxFees[index_in_template]);
        int64_t nTxSigOps = pblocktemplate->vTxSigOpsCost[index_in_template];
        if (fPreSegWit) {
            CHECK_NONFATAL(nTxSigOps % WITNESS_SCALE_FACTOR == 0);
            nTxSigOps /= WITNESS_SCALE_FACTOR;
        }
        entry.pushKV("sigops", nTxSigOps);
        entry.pushKV("weight", GetTransactionWeight(tx));

        transactions.push_back(entry);
    }

    UniValue aux(UniValue::VOBJ);

    arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBits);

    UniValue aMutable(UniValue::VARR);
    aMutable.push_back("time");
    aMutable.push_back("transactions");
    aMutable.push_back("prevblock");

    UniValue result(UniValue::VOBJ);
    result.pushKV("capabilities", aCaps);

    UniValue aRules(UniValue::VARR);
    aRules.push_back("csv");
    if (!fPreSegWit) aRules.push_back("!segwit");
    UniValue vbavailable(UniValue::VOBJ);
    for (int j = 0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
        Consensus::DeploymentPos pos = Consensus::DeploymentPos(j);
        ThresholdState state = VersionBitsState(pindexPrev, consensusParams, pos, versionbitscache);
        switch (state) {
            case ThresholdState::DEFINED:
            case ThresholdState::FAILED:
                // Not exposed to GBT at all
                break;
            case ThresholdState::LOCKED_IN:
                // Ensure bit is set in block version
                pblock->nVersion |= VersionBitsMask(consensusParams, pos);
                // FALL THROUGH to get vbavailable set...
            case ThresholdState::STARTED:
            {
                const struct VBDeploymentInfo& vbinfo = VersionBitsDeploymentInfo[pos];
                vbavailable.pushKV(gbt_vb_name(pos), consensusParams.vDeployments[pos].bit);
                if (setClientRules.find(vbinfo.name) == setClientRules.end()) {
                    if (!vbinfo.gbt_force) {
                        // If the client doesn't support this, don't indicate it in the [default] version
                        pblock->nVersion &= ~VersionBitsMask(consensusParams, pos);
                    }
                }
                break;
            }
            case ThresholdState::ACTIVE:
            {
                // Add to rules only
                const struct VBDeploymentInfo& vbinfo = VersionBitsDeploymentInfo[pos];
                aRules.push_back(gbt_vb_name(pos));
                if (setClientRules.find(vbinfo.name) == setClientRules.end()) {
                    // Not supported by the client; make sure it's safe to proceed
                    if (!vbinfo.gbt_force) {
                        // If we do anything other than throw an exception here, be sure version/force isn't sent to old clients
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Support for '%s' rule requires explicit client support", vbinfo.name));
                    }
                }
                break;
            }
        }
    }
    result.pushKV("version", pblock->nVersion);
    result.pushKV("rules", aRules);
    result.pushKV("vbavailable", vbavailable);
    result.pushKV("vbrequired", int(0));

    if (nMaxVersionPreVB >= 2) {
        // If VB is supported by the client, nMaxVersionPreVB is -1, so we won't get here
        // Because BIP 34 changed how the generation transaction is serialized, we can only use version/force back to v2 blocks
        // This is safe to do [otherwise-]unconditionally only because we are throwing an exception above if a non-force deployment gets activated
        // Note that this can probably also be removed entirely after the first BIP9 non-force deployment (ie, probably segwit) gets activated
        aMutable.push_back("version/force");
    }

    result.pushKV("previousblockhash", pblock->hashPrevBlock.GetHex());
    result.pushKV("transactions", transactions);
    result.pushKV("coinbaseaux", aux);
    result.pushKV("coinbasevalue", (int64_t)pblock->vtx[0]->vout[0].nValue);
    result.pushKV("longpollid", ::ChainActive().Tip()->GetBlockHash().GetHex() + ToString(nTransactionsUpdatedLast));
    result.pushKV("target", hashTarget.GetHex());
    result.pushKV("mintime", (int64_t)pindexPrev->GetMedianTimePast()+1);
    result.pushKV("mutable", aMutable);
    result.pushKV("noncerange", "00000000ffffffff");
    int64_t nSigOpLimit = MAX_BLOCK_SIGOPS_COST;
    int64_t nSizeLimit = MAX_BLOCK_SERIALIZED_SIZE;
    if (fPreSegWit) {
        CHECK_NONFATAL(nSigOpLimit % WITNESS_SCALE_FACTOR == 0);
        nSigOpLimit /= WITNESS_SCALE_FACTOR;
        CHECK_NONFATAL(nSizeLimit % WITNESS_SCALE_FACTOR == 0);
        nSizeLimit /= WITNESS_SCALE_FACTOR;
    }
    result.pushKV("sigoplimit", nSigOpLimit);
    result.pushKV("sizelimit", nSizeLimit);
    if (!fPreSegWit) {
        result.pushKV("weightlimit", (int64_t)MAX_BLOCK_WEIGHT);
    }
    result.pushKV("curtime", pblock->GetBlockTime());
    result.pushKV("bits", strprintf("%08x", pblock->nBits));
    result.pushKV("height", (int64_t)(pindexPrev->nHeight+1));

    if (!pblocktemplate->vchCoinbaseCommitment.empty()) {
        result.pushKV("default_witness_commitment", HexStr(pblocktemplate->vchCoinbaseCommitment.begin(), pblocktemplate->vchCoinbaseCommitment.end()));
    }

    return result;
}

class submitblock_StateCatcher final : public CValidationInterface
{
public:
    uint256 hash;
    bool found;
    BlockValidationState state;

    explicit submitblock_StateCatcher(const uint256 &hashIn) : hash(hashIn), found(false), state() {}

protected:
    void BlockChecked(const CBlock& block, const BlockValidationState& stateIn) override {
        if (block.GetHash() != hash)
            return;
        found = true;
        state = stateIn;
    }
};

static UniValue submitblock(const JSONRPCRequest& request)
{
    // We allow 2 arguments for compliance with BIP22. Argument 2 is ignored.
            RPCHelpMan{"submitblock",
                "\nAttempts to submit new block to network.\n"
                "See https://en.vitae.it/wiki/BIP_0022 for full specification.\n",
                {
                    {"hexdata", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hex-encoded block data to submit"},
                    {"dummy", RPCArg::Type::STR, /* default */ "ignored", "dummy value, for compatibility with BIP22. This value is ignored."},
                },
                RPCResult{RPCResult::Type::NONE, "", "Returns JSON Null when valid, a string according to BIP22 otherwise"},
                RPCExamples{
                    HelpExampleCli("submitblock", "\"mydata\"")
            + HelpExampleRpc("submitblock", "\"mydata\"")
                },
            }.Check(request);

    std::shared_ptr<CBlock> blockptr = std::make_shared<CBlock>();
    CBlock& block = *blockptr;
    if (!DecodeHexBlk(block, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
    }

    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block does not start with a coinbase");
    }

    uint256 hash = block.GetHash();
    {
        LOCK(cs_main);
        const CBlockIndex* pindex = LookupBlockIndex(hash);
        if (pindex) {
            if (pindex->IsValid(BLOCK_VALID_SCRIPTS)) {
                return "duplicate";
            }
            if (pindex->nStatus & BLOCK_FAILED_MASK) {
                return "duplicate-invalid";
            }
        }
    }

    {
        LOCK(cs_main);
        const CBlockIndex* pindex = LookupBlockIndex(block.hashPrevBlock);
        if (pindex) {
            UpdateUncommittedBlockStructures(block, pindex, Params().GetConsensus());
        }
    }

    bool new_block;
    auto sc = std::make_shared<submitblock_StateCatcher>(block.GetHash());
    RegisterSharedValidationInterface(sc);
    bool accepted = ProcessNewBlock(Params(), blockptr, /* fForceProcessing */ true, /* fNewBlock */ &new_block);
    UnregisterSharedValidationInterface(sc);
    if (!new_block && accepted) {
        return "duplicate";
    }
    if (!sc->found) {
        return "inconclusive";
    }
    return BIP22ValidationResult(sc->state);
}

static UniValue submitheader(const JSONRPCRequest& request)
{
            RPCHelpMan{"submitheader",
                "\nDecode the given hexdata as a header and submit it as a candidate chain tip if valid."
                "\nThrows when the header is invalid.\n",
                {
                    {"hexdata", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hex-encoded block header data"},
                },
                RPCResult{
                    RPCResult::Type::NONE, "", "None"},
                RPCExamples{
                    HelpExampleCli("submitheader", "\"aabbcc\"") +
                    HelpExampleRpc("submitheader", "\"aabbcc\"")
                },
            }.Check(request);

    CBlockHeader h;
    if (!DecodeHexBlockHeader(h, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block header decode failed");
    }
    {
        LOCK(cs_main);
        if (!LookupBlockIndex(h.hashPrevBlock)) {
            throw JSONRPCError(RPC_VERIFY_ERROR, "Must submit previous header (" + h.hashPrevBlock.GetHex() + ") first");
        }
    }

    BlockValidationState state;
    ProcessNewBlockHeaders({h}, state, Params());
    if (state.IsValid()) return NullUniValue;
    if (state.IsError()) {
        throw JSONRPCError(RPC_VERIFY_ERROR, state.ToString());
    }
    throw JSONRPCError(RPC_VERIFY_ERROR, state.GetRejectReason());
}

static UniValue estimatesmartfee(const JSONRPCRequest& request)
{
            RPCHelpMan{"estimatesmartfee",
                "\nEstimates the approximate fee per kilobyte needed for a transaction to begin\n"
                "confirmation within conf_target blocks if possible and return the number of blocks\n"
                "for which the estimate is valid. Uses virtual transaction size as defined\n"
                "in BIP 141 (witness data is discounted).\n",
                {
                    {"conf_target", RPCArg::Type::NUM, RPCArg::Optional::NO, "Confirmation target in blocks (1 - 1008)"},
                    {"estimate_mode", RPCArg::Type::STR, /* default */ "CONSERVATIVE", "The fee estimate mode.\n"
            "                   Whether to return a more conservative estimate which also satisfies\n"
            "                   a longer history. A conservative estimate potentially returns a\n"
            "                   higher feerate and is more likely to be sufficient for the desired\n"
            "                   target, but is not as responsive to short term drops in the\n"
            "                   prevailing fee market.  Must be one of:\n"
            "       \"UNSET\"\n"
            "       \"ECONOMICAL\"\n"
            "       \"CONSERVATIVE\""},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "feerate", /* optional */ true, "estimate fee rate in " + CURRENCY_UNIT + "/kB (only present if no errors were encountered)"},
                        {RPCResult::Type::ARR, "errors", "Errors encountered during processing",
                            {
                                {RPCResult::Type::STR, "", "error"},
                            }},
                        {RPCResult::Type::NUM, "blocks", "block number where estimate was found\n"
            "The request target will be clamped between 2 and the highest target\n"
            "fee estimation is able to return based on how long it has been running.\n"
            "An error is returned if not enough transactions and blocks\n"
            "have been observed to make an estimate for any number of blocks."},
                    }},
                RPCExamples{
                    HelpExampleCli("estimatesmartfee", "6")
                },
            }.Check(request);

    RPCTypeCheck(request.params, {UniValue::VNUM, UniValue::VSTR});
    RPCTypeCheckArgument(request.params[0], UniValue::VNUM);
    unsigned int max_target = ::feeEstimator.HighestTargetTracked(FeeEstimateHorizon::LONG_HALFLIFE);
    unsigned int conf_target = ParseConfirmTarget(request.params[0], max_target);
    bool conservative = true;
    if (!request.params[1].isNull()) {
        FeeEstimateMode fee_mode;
        if (!FeeModeFromString(request.params[1].get_str(), fee_mode)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid estimate_mode parameter");
        }
        if (fee_mode == FeeEstimateMode::ECONOMICAL) conservative = false;
    }

    UniValue result(UniValue::VOBJ);
    UniValue errors(UniValue::VARR);
    FeeCalculation feeCalc;
    CFeeRate feeRate = ::feeEstimator.estimateSmartFee(conf_target, &feeCalc, conservative);
    if (feeRate != CFeeRate(0)) {
        result.pushKV("feerate", ValueFromAmount(feeRate.GetFeePerK()));
    } else {
        errors.push_back("Insufficient data or no feerate found");
        result.pushKV("errors", errors);
    }
    result.pushKV("blocks", feeCalc.returnedTarget);
    return result;
}

static UniValue estimaterawfee(const JSONRPCRequest& request)
{
            RPCHelpMan{"estimaterawfee",
                "\nWARNING: This interface is unstable and may disappear or change!\n"
                "\nWARNING: This is an advanced API call that is tightly coupled to the specific\n"
                "         implementation of fee estimation. The parameters it can be called with\n"
                "         and the results it returns will change if the internal implementation changes.\n"
                "\nEstimates the approximate fee per kilobyte needed for a transaction to begin\n"
                "confirmation within conf_target blocks if possible. Uses virtual transaction size as\n"
                "defined in BIP 141 (witness data is discounted).\n",
                {
                    {"conf_target", RPCArg::Type::NUM, RPCArg::Optional::NO, "Confirmation target in blocks (1 - 1008)"},
                    {"threshold", RPCArg::Type::NUM, /* default */ "0.95", "The proportion of transactions in a given feerate range that must have been\n"
            "               confirmed within conf_target in order to consider those feerates as high enough and proceed to check\n"
            "               lower buckets."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "Results are returned for any horizon which tracks blocks up to the confirmation target",
                    {
                        {RPCResult::Type::OBJ, "short", /* optional */ true, "estimate for short time horizon",
                            {
                                {RPCResult::Type::NUM, "feerate", /* optional */ true, "estimate fee rate in " + CURRENCY_UNIT + "/kB"},
                                {RPCResult::Type::NUM, "decay", "exponential decay (per block) for historical moving average of confirmation data"},
                                {RPCResult::Type::NUM, "scale", "The resolution of confirmation targets at this time horizon"},
                                {RPCResult::Type::OBJ, "pass", /* optional */ true, "information about the lowest range of feerates to succeed in meeting the threshold",
                                {
                                        {RPCResult::Type::NUM, "startrange", "start of feerate range"},
                                        {RPCResult::Type::NUM, "endrange", "end of feerate range"},
                                        {RPCResult::Type::NUM, "withintarget", "number of txs over history horizon in the feerate range that were confirmed within target"},
                                        {RPCResult::Type::NUM, "totalconfirmed", "number of txs over history horizon in the feerate range that were confirmed at any point"},
                                        {RPCResult::Type::NUM, "inmempool", "current number of txs in mempool in the feerate range unconfirmed for at least target blocks"},
                                        {RPCResult::Type::NUM, "leftmempool", "number of txs over history horizon in the feerate range that left mempool unconfirmed after target"},
                                }},
                                {RPCResult::Type::OBJ, "fail", /* optional */ true, "information about the highest range of feerates to fail to meet the threshold",
                                {
                                    {RPCResult::Type::ELISION, "", ""},
                                }},
                                {RPCResult::Type::ARR, "errors", /* optional */ true, "Errors encountered during processing",
                                {
                                    {RPCResult::Type::STR, "error", ""},
                                }},
                        }},
                        {RPCResult::Type::OBJ, "medium", /* optional */ true, "estimate for medium time horizon",
                        {
                            {RPCResult::Type::ELISION, "", ""},
                        }},
                        {RPCResult::Type::OBJ, "long", /* optional */ true, "estimate for long time horizon",
                        {
                            {RPCResult::Type::ELISION, "", ""},
                        }},
                    }},
                RPCExamples{
                    HelpExampleCli("estimaterawfee", "6 0.9")
                },
            }.Check(request);

    RPCTypeCheck(request.params, {UniValue::VNUM, UniValue::VNUM}, true);
    RPCTypeCheckArgument(request.params[0], UniValue::VNUM);
    unsigned int max_target = ::feeEstimator.HighestTargetTracked(FeeEstimateHorizon::LONG_HALFLIFE);
    unsigned int conf_target = ParseConfirmTarget(request.params[0], max_target);
    double threshold = 0.95;
    if (!request.params[1].isNull()) {
        threshold = request.params[1].get_real();
    }
    if (threshold < 0 || threshold > 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid threshold");
    }

    UniValue result(UniValue::VOBJ);

    for (const FeeEstimateHorizon horizon : {FeeEstimateHorizon::SHORT_HALFLIFE, FeeEstimateHorizon::MED_HALFLIFE, FeeEstimateHorizon::LONG_HALFLIFE}) {
        CFeeRate feeRate;
        EstimationResult buckets;

        // Only output results for horizons which track the target
        if (conf_target > ::feeEstimator.HighestTargetTracked(horizon)) continue;

        feeRate = ::feeEstimator.estimateRawFee(conf_target, threshold, horizon, &buckets);
        UniValue horizon_result(UniValue::VOBJ);
        UniValue errors(UniValue::VARR);
        UniValue passbucket(UniValue::VOBJ);
        passbucket.pushKV("startrange", round(buckets.pass.start));
        passbucket.pushKV("endrange", round(buckets.pass.end));
        passbucket.pushKV("withintarget", round(buckets.pass.withinTarget * 100.0) / 100.0);
        passbucket.pushKV("totalconfirmed", round(buckets.pass.totalConfirmed * 100.0) / 100.0);
        passbucket.pushKV("inmempool", round(buckets.pass.inMempool * 100.0) / 100.0);
        passbucket.pushKV("leftmempool", round(buckets.pass.leftMempool * 100.0) / 100.0);
        UniValue failbucket(UniValue::VOBJ);
        failbucket.pushKV("startrange", round(buckets.fail.start));
        failbucket.pushKV("endrange", round(buckets.fail.end));
        failbucket.pushKV("withintarget", round(buckets.fail.withinTarget * 100.0) / 100.0);
        failbucket.pushKV("totalconfirmed", round(buckets.fail.totalConfirmed * 100.0) / 100.0);
        failbucket.pushKV("inmempool", round(buckets.fail.inMempool * 100.0) / 100.0);
        failbucket.pushKV("leftmempool", round(buckets.fail.leftMempool * 100.0) / 100.0);

        // CFeeRate(0) is used to indicate error as a return value from estimateRawFee
        if (feeRate != CFeeRate(0)) {
            horizon_result.pushKV("feerate", ValueFromAmount(feeRate.GetFeePerK()));
            horizon_result.pushKV("decay", buckets.decay);
            horizon_result.pushKV("scale", (int)buckets.scale);
            horizon_result.pushKV("pass", passbucket);
            // buckets.fail.start == -1 indicates that all buckets passed, there is no fail bucket to output
            if (buckets.fail.start != -1) horizon_result.pushKV("fail", failbucket);
        } else {
            // Output only information that is still meaningful in the event of error
            horizon_result.pushKV("decay", buckets.decay);
            horizon_result.pushKV("scale", (int)buckets.scale);
            horizon_result.pushKV("fail", failbucket);
            errors.push_back("Insufficient data or no feerate found which meets threshold");
            horizon_result.pushKV("errors",errors);
        }
        result.pushKV(StringForFeeEstimateHorizon(horizon), horizon_result);
    }
    return result;
}

UniValue masternodelist(const JSONRPCRequest& request)
{


    RPCHelpMan{"masternodelist",
        "\nShow all masternode list with filter .\n",
        {
            {
                {"mode", RPCArg::Type::STR, /*default*/ "status", "The name of spork (to be set) or show to display all current spork values"},
                {"filter", RPCArg::Type::NUM, /*default*/ "\"\"", "The value of spork, in epoch time"},
            }
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::ARR, "", "contents of mn",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR_HEX, "status", "status of masternode"},
                                {RPCResult::Type::STR_HEX, "protocol", "protocol of masternode"},
                                {RPCResult::Type::STR_HEX, "pubkey", "public key associated with masternode"},
                                {RPCResult::Type::STR_HEX, "vin", "transaction id "},
                                {RPCResult::Type::STR_HEX, "lastseen", "last seen by network"},
                                {RPCResult::Type::STR_HEX, "activeseconds", "active till"},
                            }},
                    }},
            }},
        RPCExamples{
            HelpExampleCli("masternodelist", "full")
    + HelpExampleRpc("masternodelist", "full")
        },
    }.Check(request);

    std::string strMode = "status";
    std::string strFilter = "";

    if (!request.params[0].isNull())
        strMode = request.params[0].get_str();
    if (!request.params[1].isNull())
        strFilter = request.params[1].get_str();

    //if (request.params.size() >= 1) strMode = request.params[0].get_str();
    //if (request.params.size() == 2) strFilter = request.params[1].get_str();

//    if (request.fHelp ||
//            (strMode != "status" && strMode != "vin" && strMode != "pubkey" && strMode != "lastseen" && strMode != "activeseconds" && strMode != "rank"
//             && strMode != "protocol" && strMode != "full" && strMode != "votes" && strMode != "donation" && strMode != "pose"))
//    {
//        throw runtime_error(
//                    "masternodelist ( \"mode\" \"filter\" )\n"
//                    "Get a list of masternodes in different modes\n"
//                    "\nArguments:\n"
//                    "1. \"mode\"      (string, optional/required to use filter, defaults = status) The mode to run list in\n"
//                    "2. \"filter\"    (string, optional) Filter results. Partial match by IP by default in all modes, additional matches in some modes\n"
//                    "\nAvailable modes:\n"
//                    "  activeseconds  - Print number of seconds masternode recognized by the network as enabled\n"
//                    "  donation       - Show donation settings\n"
//                    "  full           - Print info in format 'status protocol pubkey vin lastseen activeseconds' (can be additionally filtered, partial match)\n"
//                    "  lastseen       - Print timestamp of when a masternode was last seen on the network\n"
//                    "  pose           - Print Proof-of-Service score\n"
//                    "  protocol       - Print protocol of a masternode (can be additionally filtered, exact match))\n"
//                    "  pubkey         - Print public key associated with a masternode (can be additionally filtered, partial match)\n"
//                    "  rank           - Print rank of a masternode based on current block\n"
//                    "  status         - Print masternode status: ENABLED / EXPIRED / VIN_SPENT / REMOVE / POS_ERROR (can be additionally filtered, partial match)\n"
//                    "  vin            - Print vin associated with a masternode (can be additionally filtered, partial match)\n"
//                    "  votes          - Print all masternode votes for a Bitcoin initiative (can be additionally filtered, partial match)\n"
//                    );
//    }

    //Object obj;
    UniValue obj(UniValue::VOBJ);
    if (strMode == "rank") {
        std::vector<pair<int, CMasternode> > vMasternodeRanks = mnodeman.GetMasternodeRanks(::ChainActive().Tip()->nHeight);
        typedef std::pair<int, CMasternode>s;
        for( s &s: vMasternodeRanks) {
            std::string strAddr = s.second.addr.ToString();
            if(strFilter !="" && strAddr.find(strFilter) == string::npos) continue;
            obj.pushKV(strAddr,       s.first);
        }
    } else {
        std::vector<CMasternode> vMasternodes = mnodeman.GetFullMasternodeVector();
        for(CMasternode& mn: vMasternodes) {
            std::string strAddr = mn.addr.ToString();
            if (strMode == "activeseconds") {
                if(strFilter !="" && strAddr.find(strFilter) == string::npos) continue;
                obj.pushKV(strAddr,       (int64_t)(mn.lastTimeSeen - mn.sigTime));
            } else if (strMode == "donation") {
                CTxDestination address1;
                ExtractDestination(mn.donationAddress, address1);
                //CBitcoinAddress address2(address1);

                if(strFilter !="" && EncodeDestination(address1).find(strFilter) == string::npos &&
                        strAddr.find(strFilter) == string::npos) continue;

                std::string strOut = "";

                if(mn.donationPercentage != 0){
                    strOut = EncodeDestination(address1);
                    strOut += ":";
                    strOut += boost::lexical_cast<std::string>(mn.donationPercentage);
                }
                obj.pushKV(strAddr,       strOut.c_str());
            } else if (strMode == "full") {
                CScript pubkey;
                pubkey = GetScriptForDestination(PKHash(mn.pubkey));
                CTxDestination address1;
                ExtractDestination(pubkey, address1);
                EncodeDestination(address1);

                std::ostringstream addrStream;
                addrStream << std::setw(21) << strAddr;

                std::ostringstream stringStream;
                stringStream << setw(10) <<
                                mn.Status() << " " <<
                                mn.protocolVersion << " " <<
                                EncodeDestination(address1) << " " <<
                                addrStream.str() << " " <<
                                mn.lastTimeSeen << " " << setw(8) <<
                                (mn.lastTimeSeen - mn.sigTime);
                std::string output = stringStream.str();
                stringStream << " " << strAddr;
                if(strFilter !="" && stringStream.str().find(strFilter) == string::npos &&
                        strAddr.find(strFilter) == string::npos) continue;
                obj.pushKV(mn.vin.prevout.hash.ToString(), output);
            } else if (strMode == "lastseen") {
                if(strFilter !="" && strAddr.find(strFilter) == string::npos) continue;
                obj.pushKV(strAddr,       (int64_t)mn.lastTimeSeen);
            } else if (strMode == "protocol") {
                if(strFilter !="" && strFilter != boost::lexical_cast<std::string>(mn.protocolVersion) &&
                        strAddr.find(strFilter) == string::npos) continue;
                obj.pushKV(strAddr,       (int64_t)mn.protocolVersion);
            } else if (strMode == "pubkey") {
                CScript pubkey;
                pubkey = GetScriptForDestination(PKHash(mn.pubkey));
                CTxDestination address1;
                ExtractDestination(pubkey, address1);
                //CBitcoinAddress address2(address1);

                if(strFilter !="" && EncodeDestination(address1).find(strFilter) == string::npos &&
                        strAddr.find(strFilter) == string::npos) continue;
                obj.pushKV(strAddr,       EncodeDestination(address1).c_str());
            } else if (strMode == "pose") {
                if(strFilter !="" && strAddr.find(strFilter) == string::npos) continue;
                std::string strOut = boost::lexical_cast<std::string>(mn.nScanningErrorCount);
                obj.pushKV(strAddr,       strOut.c_str());
            } else if(strMode == "status") {
                std::string strStatus = mn.Status();
                if(strFilter !="" && strAddr.find(strFilter) == string::npos && strStatus.find(strFilter) == string::npos) continue;
                obj.pushKV(strAddr,       strStatus.c_str());
            } else if (strMode == "vin") {
                if(strFilter !="" && mn.vin.prevout.hash.ToString().find(strFilter) == string::npos &&
                        strAddr.find(strFilter) == string::npos) continue;
                obj.pushKV(strAddr,       mn.vin.prevout.hash.ToString().c_str());
            } else if(strMode == "votes"){
                std::string strStatus = "ABSTAIN";

                //voting lasts 7 days, ignore the last vote if it was older than that
                if((GetAdjustedTime() - mn.lastVote) < (60*60*8))
                {
                    if(mn.nVote == -1) strStatus = "NAY";
                    if(mn.nVote == 1) strStatus = "YEA";
                }

                if(strFilter !="" && (strAddr.find(strFilter) == string::npos && strStatus.find(strFilter) == string::npos)) continue;
                obj.pushKV(strAddr,       strStatus.c_str());
            }
        }
    }
    return obj;
}

UniValue masternode(const JSONRPCRequest& request)
{


    RPCHelpMan{"masternode",
        "Masternode commands.\n"
               "  count        - Print number of all known masternodes (optional: 'enabled', 'both')\n"
               "  current      - Print info on current masternode winner\n"
               "  debug        - Print masternode status\n"
               "  genkey       - Generate new masternodeprivkey\n"
               "  enforce      - Enforce masternode payments\n"
               "  outputs      - Print masternode compatible outputs\n"
               "  start        - Start masternode configured in bitcoin.conf\n"
               "  start-alias  - Start single masternode by assigned alias configured in masternode.conf\n"
               "  start-many   - Start all masternodes configured in masternode.conf\n"
               "  stop         - Stop masternode configured in bitcoin.conf\n"
               "  stop-alias   - Stop single masternode by assigned alias configured in masternode.conf\n"
               "  stop-many    - Stop all masternodes configured in masternode.conf\n"
               "  list         - see masternodelist, This command has been removed.\n"
               "  list-conf    - Print masternode.conf in JSON format\n"
               "  winners      - Print list of masternode winners\n",
        {
            {
                {"command", RPCArg::Type::STR, RPCArg::Optional::NO, "Command for masternode. "},
                {"passphrase", RPCArg::Type::STR, RPCArg::Optional::OMITTED,"The passPhrase to unlock wallet"},
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::ARR, "", "contents of mn",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR_HEX, "status", "status of masternode"},
                                {RPCResult::Type::STR_HEX, "protocol", "protocol of masternode"},
                                {RPCResult::Type::STR_HEX, "pubkey", "public key associated with masternode"},
                                {RPCResult::Type::STR_HEX, "vin", "transaction id "},
                                {RPCResult::Type::STR_HEX, "lastseen", "last seen by network"},
                                {RPCResult::Type::STR_HEX, "activeseconds", "active till"},
                            }},
                    }},
            }},
        RPCExamples{
            HelpExampleCli("masternode", "debug")
    + HelpExampleRpc("masternode", "debug")
        },
    }.Check(request);

//    if (request.fHelp  ||
//            (strCommand != "start" && strCommand != "start-alias" && strCommand != "start-many" && strCommand != "stop" && strCommand != "stop-alias" && strCommand != "stop-many" && strCommand != "list-conf" && strCommand != "count"  && strCommand != "enforce"
//             && strCommand != "debug" && strCommand != "current" && strCommand != "winners" && strCommand != "genkey" && strCommand != "connect" && strCommand != "outputs" /* && strCommand != "vote-many" && strCommand != "vote" */))
//        throw runtime_error(
//                "masternode \"command\"... ( \"passphrase\" )\n"
//                "Set of commands to execute masternode related actions\n"
//                "\nArguments:\n"
//                "1. \"command\"        (string or set of strings, required) The command to execute\n"
//                "2. \"passphrase\"     (string, optional) The wallet passphrase\n"
//                "\nAvailable commands:\n"
//                "  count        - Print number of all known masternodes (optional: 'enabled', 'both')\n"
//                "  current      - Print info on current masternode winner\n"
//                "  debug        - Print masternode status\n"
//                "  genkey       - Generate new masternodeprivkey\n"
//                "  enforce      - Enforce masternode payments\n"
//                "  outputs      - Print masternode compatible outputs\n"
//                "  start        - Start masternode configured in bitcoin.conf\n"
//                "  start-alias  - Start single masternode by assigned alias configured in masternode.conf\n"
//                "  start-many   - Start all masternodes configured in masternode.conf\n"
//                "  stop         - Stop masternode configured in bitcoin.conf\n"
//                "  stop-alias   - Stop single masternode by assigned alias configured in masternode.conf\n"
//                "  stop-many    - Stop all masternodes configured in masternode.conf\n"
//                "  list         - see masternodelist, This command has been removed.\n"
//                "  list-conf    - Print masternode.conf in JSON format\n"
//                "  winners      - Print list of masternode winners\n"
//                "  vote-many    - Not implemented\n"
//                "  vote         - Not implemented\n"
//                );
    string strCommand;
    if (request.params.size() >= 1)
        strCommand = request.params[0].get_str();

    /*std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwalletMain = wallet.get();*/

    if (strCommand == "stop")
    {
        if(!fMasterNode) return "you must set masternode=1 in the configuration";

        for (const std::shared_ptr<CWallet>& pwalletMain : GetWallets()) {
            if(pwalletMain->IsLocked()) {
                SecureString strWalletPass;
                strWalletPass.reserve(100);

                if (!request.params[1].isNull()){
                    strWalletPass = request.params[1].get_str().c_str();
                } else {
                    throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
                }

                if(!pwalletMain->Unlock(strWalletPass)){
                    return "incorrect passphrase";
                }
            }

            std::string errorMessage;
            if(!activeMasternode.StopMasterNode(errorMessage)) {
                return "stop failed: " + errorMessage;
            }
            pwalletMain->Lock();
            CService service2(LookupNumeric(strMasterNodeAddr.c_str(), 0));
            CAddress addr_(service2, NODE_NONE);
            g_rpc_node->connman->OpenNetworkConnection(addr_, false, NULL, addr_.ToString().c_str());

            if(activeMasternode.status == MASTERNODE_STOPPED) return "successfully stopped masternode";
            if(activeMasternode.status == MASTERNODE_NOT_CAPABLE) return "not capable masternode";
        }

        return "unknown";
    }

    if (strCommand == "stop-alias")
    {
        if (request.params.size() < 2){
            throw JSONRPCError(
                    RPC_INVALID_PARAMETER,"command needs at least 2 parameters");

        }
        std::string alias;
        if (!request.params[1].isNull())
            alias = request.params[1].get_str().c_str();


        for (const std::shared_ptr<CWallet>& pwalletMain : GetWallets()) {
            if(pwalletMain->IsLocked()) {
                SecureString strWalletPass;
                strWalletPass.reserve(100);

                if (!request.params[2].isNull()){
                    strWalletPass = request.params[2].get_str().c_str();
                } else {
                    throw JSONRPCError(
                            RPC_WALLET_UNLOCK_NEEDED,"Error: Wallet Locked");
                }

                if(!pwalletMain->Unlock(strWalletPass)){
                    return "incorrect passphrase";
                }
            }
        }

        bool found = false;

        //Object statusObj;
        UniValue statusObj(UniValue::VOBJ);
        statusObj.pushKV("alias", alias);

        for(CMasternodeConfig::CMasternodeEntry mne: masternodeConfig.getEntries()) {
            if(mne.getAlias() == alias) {
                found = true;
                std::string errorMessage;
                bool result = activeMasternode.StopMasterNode(mne.getIp(), mne.getPrivKey(), errorMessage);

                statusObj.pushKV("result", result ? "successful" : "failed");
                if(!result) {
                    statusObj.pushKV("errorMessage", errorMessage);
                }
                break;
            }
        }

        if(!found) {
            statusObj.pushKV("result", "failed");
            statusObj.pushKV("errorMessage", "could not find alias in config. Verify with list-conf.");
        }

        //pwalletMain->Lock();

        return statusObj;
    }

    if (strCommand == "stop-many")
    {
        for (const std::shared_ptr<CWallet>& pwalletMain : GetWallets()) {
            if(pwalletMain->IsLocked()) {
                SecureString strWalletPass;
                strWalletPass.reserve(100);

                if (!request.params[1].isNull()){
                    strWalletPass = request.params[1].get_str().c_str();
                } else {
                    throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                                "Your wallet is locked, passphrase is required");
                }

                if(!pwalletMain->Unlock(strWalletPass)){
                    return "incorrect passphrase";
                }
            }
        }

        int total = 0;
        int successful = 0;
        int fail = 0;

        //Object resultsObj;
        UniValue resultsObj(UniValue::VOBJ);

        for (CMasternodeConfig::CMasternodeEntry mne: masternodeConfig.getEntries()) {
            total++;

            std::string errorMessage;
            bool result = activeMasternode.StopMasterNode(mne.getIp(), mne.getPrivKey(), errorMessage);

            //Object statusObj;
            UniValue statusObj(UniValue::VOBJ);
            statusObj.pushKV("alias", mne.getAlias());
            statusObj.pushKV("result", result ? "successful" : "failed");

            if(result) {
                successful++;
            } else {
                fail++;
                statusObj.pushKV("errorMessage", errorMessage);
            }

            resultsObj.pushKV("status", statusObj);
        }
        //pwalletMain->Lock();

        //Object returnObj;
        UniValue returnObj(UniValue::VOBJ);
        returnObj.pushKV("overall", "Successfully stopped " + boost::lexical_cast<std::string>(successful) + " masternodes, failed to stop " +
                                 boost::lexical_cast<std::string>(fail) + ", total " + boost::lexical_cast<std::string>(total));
        returnObj.pushKV("detail", resultsObj);

        return returnObj;
    }

    if (strCommand == "count")
    {
        if (request.params.size() > 2){
            throw JSONRPCError(RPC_INVALID_PARAMS,
                        "too many parameters");
        }

        return mnodeman.size();
    }

    if (strCommand == "start")
    {
        if(!fMasterNode) return "you must set masternode=1 in the configuration";

        // get all wallets
        for (const std::shared_ptr<CWallet>& pwalletMain : GetWallets()) {
            if(pwalletMain->IsLocked()) {
                SecureString strWalletPass;
                strWalletPass.reserve(100);

                if (!request.params[1].isNull()){
                    strWalletPass = request.params[1].get_str().c_str();
                } else {
                    throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                                "Your wallet is locked, passphrase is required");
                }

                if(!pwalletMain->Unlock(strWalletPass)){
                    return "incorrect passphrase";
                }
            }

            if(activeMasternode.status != MASTERNODE_REMOTELY_ENABLED && activeMasternode.status != MASTERNODE_IS_CAPABLE){
                activeMasternode.status = MASTERNODE_NOT_PROCESSED; // TODO: consider better way
                std::string errorMessage;
                activeMasternode.ManageStatus();
                pwalletMain->Lock();
            }

            if(activeMasternode.status == MASTERNODE_REMOTELY_ENABLED) return "masternode started remotely";
            if(activeMasternode.status == MASTERNODE_INPUT_TOO_NEW) return "masternode input must have at least 15 confirmations";
            if(activeMasternode.status == MASTERNODE_STOPPED) return "masternode is stopped";
            if(activeMasternode.status == MASTERNODE_IS_CAPABLE) return "successfully started masternode";
            if(activeMasternode.status == MASTERNODE_NOT_CAPABLE) return "not capable masternode: " + activeMasternode.notCapableReason;
            if(activeMasternode.status == MASTERNODE_SYNC_IN_PROCESS) return "sync in process. Must wait until client is synced to start.";

        }

        return "unknown";
    }

    if (strCommand == "start-alias")
    {
        if (request.params.size() < 2){
            throw JSONRPCError(
                    RPC_INVALID_PARAMETER,"command needs at least 2 parameters");
        }
        std::string alias;
        if (!request.params[1].isNull())
            alias= request.params[1].get_str().c_str();

        for (const std::shared_ptr<CWallet>& pwalletMain : GetWallets()) {
            if(pwalletMain->IsLocked()) {
                SecureString strWalletPass;
                strWalletPass.reserve(100);

                if (!request.params[2].isNull()){
                    strWalletPass = request.params[2].get_str().c_str();
                } else {
                    throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                                       "Your wallet is locked, passphrase is required");
                }

                if(!pwalletMain->Unlock(strWalletPass)){
                    return "incorrect passphrase";
                }
            }
        }

        bool found = false;

        //Object statusObj;
        UniValue statusObj(UniValue::VOBJ);
        statusObj.pushKV("alias", alias);

        for(CMasternodeConfig::CMasternodeEntry mne: masternodeConfig.getEntries()) {
            if(mne.getAlias() == alias) {
                found = true;
                std::string errorMessage;

                std::string strDonateAddress = mne.getDonationAddress();
                std::string strDonationPercentage = mne.getDonationPercentage();

                bool result = activeMasternode.Register(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), strDonateAddress, strDonationPercentage, errorMessage);

                statusObj.pushKV("result", result ? "successful" : "failed");
                if(!result) {
                    statusObj.pushKV("errorMessage", errorMessage);
                }
                break;
            }
        }

        if(!found) {
            statusObj.pushKV("result", "failed");
            statusObj.pushKV("errorMessage", "could not find alias in config. Verify with list-conf.");
        }

        //pwalletMain->Lock();
        return statusObj;

    }

    if (strCommand == "start-many")
    {
        for (const std::shared_ptr<CWallet>& pwalletMain : GetWallets()) {
            if(pwalletMain->IsLocked()) {
                SecureString strWalletPass;
                strWalletPass.reserve(100);

                if (!request.params[1].isNull()){
                    strWalletPass = request.params[1].get_str().c_str();
                } else {
                    throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                                       "Your wallet is locked, passphrase is required");
                }

                if(!pwalletMain->Unlock(strWalletPass)){
                    return "incorrect passphrase";
                }
            }
        }

        std::vector<CMasternodeConfig::CMasternodeEntry> mnEntries;
        mnEntries = masternodeConfig.getEntries();

        int total = 0;
        int successful = 0;
        int fail = 0;

        //Object resultsObj;
        UniValue resultsObj(UniValue::VOBJ);

        for(CMasternodeConfig::CMasternodeEntry mne: masternodeConfig.getEntries()) {
            total++;

            std::string errorMessage;

            std::string strDonateAddress = mne.getDonationAddress();
            std::string strDonationPercentage = mne.getDonationPercentage();

            bool result = activeMasternode.Register(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), strDonateAddress, strDonationPercentage, errorMessage);

            //Object statusObj;
            UniValue statusObj(UniValue::VOBJ);
            statusObj.pushKV("alias", mne.getAlias());
            statusObj.pushKV("result", result ? "successful" : "failed");

            if(result) {
                successful++;
            } else {
                fail++;
                statusObj.pushKV("errorMessage", errorMessage);
            }

            resultsObj.pushKV("status", statusObj);
        }
        //pwalletMain->Lock();

        //Object returnObj;
        UniValue returnObj(UniValue::VOBJ);
        returnObj.pushKV("overall", "Successfully started " + boost::lexical_cast<std::string>(successful) + " masternodes, failed to start " +
                                 boost::lexical_cast<std::string>(fail) + ", total " + boost::lexical_cast<std::string>(total));
        returnObj.pushKV("detail", resultsObj);

        return returnObj;
    }

    if (strCommand == "debug")
    {
        if(activeMasternode.status == MASTERNODE_REMOTELY_ENABLED) return "masternode started remotely";
        if(activeMasternode.status == MASTERNODE_INPUT_TOO_NEW) return "masternode input must have at least 15 confirmations";
        if(activeMasternode.status == MASTERNODE_IS_CAPABLE) return "successfully started masternode";
        if(activeMasternode.status == MASTERNODE_STOPPED) return "masternode is stopped";
        if(activeMasternode.status == MASTERNODE_NOT_CAPABLE) return "not capable masternode: " + activeMasternode.notCapableReason;
        if(activeMasternode.status == MASTERNODE_SYNC_IN_PROCESS) return "sync in process. Must wait until client is synced to start.";

        CTxIn vin = CTxIn();
        //CPubKey pubkey = CScript();
        CPubKey pubkey;
        CKey key;
        bool found = activeMasternode.GetMasterNodeVin(vin, pubkey, key);
        if(!found){
            return "Missing masternode input, please look at the documentation for instructions on masternode creation";
        } else {
            return "No problems were found";
        }
    }

    if (strCommand == "create")
    {

        return "Not implemented yet, please look at the documentation for instructions on masternode creation";
    }

    if (strCommand == "current")
    {
        CMasternode* winner = mnodeman.GetCurrentMasterNode(1);
        if(winner) {
            //Object obj;
            UniValue obj(UniValue::VOBJ);
            CScript pubkey;
            pubkey = GetScriptForDestination(PKHash(winner->pubkey));
            CTxDestination address1;
            ExtractDestination(pubkey, address1);
            //CBitcoinAddress address2(address1);

            obj.pushKV("IP:port",       winner->addr.ToString().c_str());
            obj.pushKV("protocol",      (int64_t)winner->protocolVersion);
            obj.pushKV("vin",           winner->vin.prevout.hash.ToString().c_str());
            obj.pushKV("pubkey",        EncodeDestination(address1));
            obj.pushKV("lastseen",      (int64_t)winner->lastTimeSeen);
            obj.pushKV("activeseconds", (int64_t)(winner->lastTimeSeen - winner->sigTime));
            return obj;
        }

        return "unknown";
    }

    if (strCommand == "genkey")
    {
        CKey secret;
        secret.MakeNewKey(false);

        return EncodeSecret(secret);
    }

    if (strCommand == "winners")
    {
        //Object obj;
        UniValue obj(UniValue::VOBJ);

        for(int nHeight = ::ChainActive().Tip()->nHeight-10; nHeight < ::ChainActive().Tip()->nHeight+20; nHeight++)
        {
            CScript payee;
            if(masternodePayments.GetBlockPayee(nHeight, payee)){
                CTxDestination address1;
                ExtractDestination(payee, address1);
                //CBitcoinAddress address2(address1);
                obj.pushKV(boost::lexical_cast<std::string>(nHeight),       EncodeDestination(address1));
            } else {
                obj.pushKV(boost::lexical_cast<std::string>(nHeight),       "");
            }
        }

        return obj;
    }

    if(strCommand == "enforce")
    {
        return (uint64_t)enforceMasternodePaymentsTime;
    }

    if(strCommand == "connect")
    {
        std::string strAddress = "";
        if (!request.params[1].isNull()){
            strAddress = request.params[1].get_str().c_str();
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "Masternode address required");
        }

        CService service2(LookupNumeric(strAddress.c_str(), 0));
        CAddress addr_(service2, NODE_NONE);

        /*bool pnode1 =*/ g_rpc_node->connman->OpenNetworkConnection(addr_, false, nullptr, addr_.ToString().c_str(), false, false, true);

        /*if(pnode1){
                return "successfully connected";
            } else {
                return "error connecting";
            }*/
        return "attempted to connect";
    }

    if(strCommand == "list-conf")
    {
        std::vector<CMasternodeConfig::CMasternodeEntry> mnEntries;
        mnEntries = masternodeConfig.getEntries();

        //Object resultObj;
        UniValue resultObj(UniValue::VOBJ);

        for(CMasternodeConfig::CMasternodeEntry mne: masternodeConfig.getEntries()) {
            //Object mnObj;
            UniValue mnObj(UniValue::VOBJ);
            mnObj.pushKV("alias", mne.getAlias());
            mnObj.pushKV("address", mne.getIp());
            mnObj.pushKV("privateKey", mne.getPrivKey());
            mnObj.pushKV("txHash", mne.getTxHash());
            mnObj.pushKV("outputIndex", mne.getOutputIndex());
            mnObj.pushKV("donationAddress", mne.getDonationAddress());
            mnObj.pushKV("donationPercent", mne.getDonationPercentage());
            resultObj.pushKV("masternode", mnObj);
        }

        return resultObj;
    }

    if (strCommand == "outputs"){
        // Find possible candidates
        vector<COutput> possibleCoins = activeMasternode.SelectCoinsMasternode();

        //Object obj;
        UniValue obj(UniValue::VOBJ);
        for (COutput& out: possibleCoins) {
            obj.pushKV(out.tx->GetHash().ToString().c_str(), boost::lexical_cast<std::string>(out.i));
        }

        return obj;

    }

    if (strCommand == "status") {
        if(!fMasterNode) return "You must set masternode=1 in the configuration";
        UniValue mnObj(UniValue::VOBJ);
        CMasternode* pmn = mnodeman.Find(activeMasternode.vin);

        if (pmn) {
            mnObj.pushKV("txhash", activeMasternode.vin.prevout.hash.ToString());
            mnObj.pushKV("outputidx", (uint64_t)activeMasternode.vin.prevout.n);
            mnObj.pushKV("netaddr", activeMasternode.service.ToString());
            //pubkeyCollateralAddress missed, need to check about it
            //mnObj.push_back(Pair("addr", CBitcoinAddress(pmn->pubKeyCollateralAddress.GetID()).ToString()));
            std::string status;
            if(activeMasternode.status == MASTERNODE_REMOTELY_ENABLED) status="masternode started remotely";
            if(activeMasternode.status == MASTERNODE_INPUT_TOO_NEW) status= "masternode input must have at least 15 confirmations";
            if(activeMasternode.status == MASTERNODE_STOPPED) status= "masternode is stopped";
            if(activeMasternode.status == MASTERNODE_IS_CAPABLE) status= "successfully started masternode";
            if(activeMasternode.status == MASTERNODE_NOT_CAPABLE) status= "not capable masternode: " + activeMasternode.notCapableReason;
            if(activeMasternode.status == MASTERNODE_SYNC_IN_PROCESS) status= "sync in process. Must wait until client is synced to start.";

            mnObj.pushKV("status", status);
            return mnObj;
        }
//        throw runtime_error("Masternode not found in the list of available masternodes. Current status: "
//                            + activeMasternode.GetStatus());
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Masternode not found in the list of available masternodes");
    }
    if (strCommand == "list") {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Command Deprecated. Please use masternodelist");
    }
    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid Command");

}


void RegisterMiningRPCCommands(CRPCTable &t)
{
// clang-format off
static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    { "mining",             "getnetworkhashps",       &getnetworkhashps,       {"nblocks","height"} },
    { "mining",             "getmininginfo",          &getmininginfo,          {} },
    { "mining",             "prioritisetransaction",  &prioritisetransaction,  {"txid","dummy","fee_delta"} },
    { "mining",             "getblocktemplate",       &getblocktemplate,       {"template_request"} },
    { "mining",             "submitblock",            &submitblock,            {"hexdata","dummy"} },
    { "mining",             "submitheader",           &submitheader,           {"hexdata"} },


    { "generating",         "generatetoaddress",      &generatetoaddress,      {"nblocks","address","maxtries"} },
    { "generating",         "generatetodescriptor",   &generatetodescriptor,   {"num_blocks","descriptor","maxtries"} },
    { "masternode",         "masternode",             &masternode,             {"strCommand"} },
    { "masternode",         "masternodelist",         &masternodelist,         {"strMode"} },

    { "util",               "estimatesmartfee",       &estimatesmartfee,       {"conf_target", "estimate_mode"} },

    { "hidden",             "estimaterawfee",         &estimaterawfee,         {"conf_target", "threshold"} },
};
// clang-format on

    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
