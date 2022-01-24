// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Copyright (c) 2020-2021 The Vitae Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <miner.h>

#include <amount.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <pow.h>
#include <primitives/transaction.h>
#include <timedata.h>
#include <util/moneystr.h>
#include <util/system.h>

#include <masternodes/masternode.h>
#include <masternodes/masternodeman.h>
#include <key_io.h>
#include <pos/blocksigner.h>
#include <masternodes/fndata.h>
#include <core_io.h>

#include <algorithm>
#include <utility>

#include <boost/thread.hpp>
#include <init.h>

int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime = std::max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());

    if (nOldTime < nNewTime)
        pblock->nTime = nNewTime;

    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks)
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);

    return nNewTime - nOldTime;
}

BlockAssembler::Options::Options() {
    blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE);
    nBlockMaxWeight = DEFAULT_BLOCK_MAX_WEIGHT;
}

BlockAssembler::BlockAssembler(const CTxMemPool& mempool, const CChainParams& params, const Options& options)
    : chainparams(params),
      m_mempool(mempool)
{
    blockMinFeeRate = options.blockMinFeeRate;
    // Limit weight to between 4K and MAX_BLOCK_WEIGHT-4K for sanity:
    nBlockMaxWeight = std::max<size_t>(4000, std::min<size_t>(MAX_BLOCK_WEIGHT - 4000, options.nBlockMaxWeight));
}

static BlockAssembler::Options DefaultOptions()
{
    // Block resource limits
    // If -blockmaxweight is not given, limit to DEFAULT_BLOCK_MAX_WEIGHT
    BlockAssembler::Options options;
    options.nBlockMaxWeight = gArgs.GetArg("-blockmaxweight", DEFAULT_BLOCK_MAX_WEIGHT);
    CAmount n = 0;
    if (gArgs.IsArgSet("-blockmintxfee") && ParseMoney(gArgs.GetArg("-blockmintxfee", ""), n)) {
        options.blockMinFeeRate = CFeeRate(n);
    } else {
        options.blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE);
    }
    return options;
}

BlockAssembler::BlockAssembler(const CTxMemPool& mempool, const CChainParams& params)
    : BlockAssembler(mempool, params, DefaultOptions()) {}

void BlockAssembler::resetBlock()
{
    inBlock.clear();

    // Reserve space for coinbase tx
    nBlockWeight = 4000;
    nBlockSigOpsCost = 400;
    fIncludeWitness = false;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;
}

Optional<int64_t> BlockAssembler::m_last_block_num_txs{nullopt};
Optional<int64_t> BlockAssembler::m_last_block_weight{nullopt};

std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock(const CScript& scriptPubKeyIn)
{
    int64_t nTimeStart = GetTimeMicros();

    resetBlock();

    pblocktemplate.reset(new CBlockTemplate());

    if(!pblocktemplate.get())
        return nullptr;
    pblock = &pblocktemplate->block; // pointer for convenience

    // Add dummy coinbase tx as first transaction
    pblock->vtx.emplace_back();
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOpsCost.push_back(-1); // updated at end

    LOCK2(cs_main, m_mempool.cs);
    CBlockIndex* pindexPrev = ::ChainActive().Tip();
    assert(pindexPrev != nullptr);
    nHeight = pindexPrev->nHeight + 1;

    pblock->nVersion = ComputeBlockVersion(pindexPrev, chainparams.GetConsensus());
    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand())
        pblock->nVersion = gArgs.GetArg("-blockversion", pblock->nVersion);

    pblock->nTime = GetAdjustedTime();
    const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();

    nLockTimeCutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST)
                       ? nMedianTimePast
                       : pblock->GetBlockTime();

    // Decide whether to include witness transactions
    // This is only needed in case the witness softfork activation is reverted
    // (which would require a very deep reorganization).
    // Note that the mempool would accept transactions with witness data before
    // IsWitnessEnabled, but we would only ever mine blocks after IsWitnessEnabled
    // unless there is a massive block reorganization with the witness softfork
    // not activated.
    // TODO: replace this with a call to main to assess validity of a mempool
    // transaction (which in most cases can be a no-op).
    fIncludeWitness = IsWitnessEnabled(pindexPrev, chainparams.GetConsensus());

    int nPackagesSelected = 0;
    int nDescendantsUpdated = 0;
    addPackageTxs(nPackagesSelected, nDescendantsUpdated);

    int64_t nTime1 = GetTimeMicros();

    m_last_block_num_txs = nBlockTx;
    m_last_block_weight = nBlockWeight;

    // Create coinbase transaction.
    CMutableTransaction coinbaseTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].scriptPubKey = scriptPubKeyIn;
    coinbaseTx.vout[0].nValue = nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus());
    coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;
    pblock->vtx[0] = MakeTransactionRef(std::move(coinbaseTx));
    pblocktemplate->vchCoinbaseCommitment = GenerateCoinbaseCommitment(*pblock, pindexPrev, chainparams.GetConsensus());
    pblocktemplate->vTxFees[0] = -nFees;


    LogPrintf("CreateNewBlock(): block weight: %u txs: %u fees: %ld sigops %d\n", GetBlockWeight(*pblock), nBlockTx, nFees, nBlockSigOpsCost);

    // Fill in header
    pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
    UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
    pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus());
    pblock->nNonce         = 0;
    pblocktemplate->vTxSigOpsCost[0] = WITNESS_SCALE_FACTOR * GetLegacySigOpCount(*pblock->vtx[0]);

    BlockValidationState state;
    if (!TestBlockValidity(state, chainparams, *pblock, pindexPrev, false, false)) {
        throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, state.ToString()));
    }
    int64_t nTime2 = GetTimeMicros();

    LogPrint(BCLog::BENCH, "CreateNewBlock() packages: %.2fms (%d packages, %d updated descendants), validity: %.2fms (total %.2fms)\n", 0.001 * (nTime1 - nTimeStart), nPackagesSelected, nDescendantsUpdated, 0.001 * (nTime2 - nTime1), 0.001 * (nTime2 - nTimeStart));

    return std::move(pblocktemplate);
}

void BlockAssembler::onlyUnconfirmed(CTxMemPool::setEntries& testSet)
{
    for (CTxMemPool::setEntries::iterator iit = testSet.begin(); iit != testSet.end(); ) {
        // Only test txs not already in the block
        if (inBlock.count(*iit)) {
            testSet.erase(iit++);
        }
        else {
            iit++;
        }
    }
}

bool BlockAssembler::TestPackage(uint64_t packageSize, int64_t packageSigOpsCost) const
{
    // TODO: switch to weight-based accounting for packages instead of vsize-based accounting.
    if (nBlockWeight + WITNESS_SCALE_FACTOR * packageSize >= nBlockMaxWeight)
        return false;
    if (nBlockSigOpsCost + packageSigOpsCost >= MAX_BLOCK_SIGOPS_COST)
        return false;
    return true;
}

// Perform transaction-level checks before adding to block:
// - transaction finality (locktime)
// - premature witness (in case segwit transactions are added to mempool before
//   segwit activation)
bool BlockAssembler::TestPackageTransactions(const CTxMemPool::setEntries& package)
{
    for (CTxMemPool::txiter it : package) {
        if (!IsFinalTx(it->GetTx(), nHeight, nLockTimeCutoff))
            return false;
        if (!fIncludeWitness && it->GetTx().HasWitness())
            return false;
    }
    return true;
}

void BlockAssembler::AddToBlock(CTxMemPool::txiter iter)
{
    pblock->vtx.emplace_back(iter->GetSharedTx());
    pblocktemplate->vTxFees.push_back(iter->GetFee());
    pblocktemplate->vTxSigOpsCost.push_back(iter->GetSigOpCost());
    nBlockWeight += iter->GetTxWeight();
    ++nBlockTx;
    nBlockSigOpsCost += iter->GetSigOpCost();
    nFees += iter->GetFee();
    inBlock.insert(iter);

    bool fPrintPriority = gArgs.GetBoolArg("-printpriority", DEFAULT_PRINTPRIORITY);
    if (fPrintPriority) {
        LogPrintf("fee %s txid %s\n",
                  CFeeRate(iter->GetModifiedFee(), iter->GetTxSize()).ToString(),
                  iter->GetTx().GetHash().ToString());
    }
}

int BlockAssembler::UpdatePackagesForAdded(const CTxMemPool::setEntries& alreadyAdded,
        indexed_modified_transaction_set &mapModifiedTx)
{
    int nDescendantsUpdated = 0;
    for (CTxMemPool::txiter it : alreadyAdded) {
        CTxMemPool::setEntries descendants;
        m_mempool.CalculateDescendants(it, descendants);
        // Insert all descendants (not yet in block) into the modified set
        for (CTxMemPool::txiter desc : descendants) {
            if (alreadyAdded.count(desc))
                continue;
            ++nDescendantsUpdated;
            modtxiter mit = mapModifiedTx.find(desc);
            if (mit == mapModifiedTx.end()) {
                CTxMemPoolModifiedEntry modEntry(desc);
                modEntry.nSizeWithAncestors -= it->GetTxSize();
                modEntry.nModFeesWithAncestors -= it->GetModifiedFee();
                modEntry.nSigOpCostWithAncestors -= it->GetSigOpCost();
                mapModifiedTx.insert(modEntry);
            } else {
                mapModifiedTx.modify(mit, update_for_parent_inclusion(it));
            }
        }
    }
    return nDescendantsUpdated;
}

// Skip entries in mapTx that are already in a block or are present
// in mapModifiedTx (which implies that the mapTx ancestor state is
// stale due to ancestor inclusion in the block)
// Also skip transactions that we've already failed to add. This can happen if
// we consider a transaction in mapModifiedTx and it fails: we can then
// potentially consider it again while walking mapTx.  It's currently
// guaranteed to fail again, but as a belt-and-suspenders check we put it in
// failedTx and avoid re-evaluation, since the re-evaluation would be using
// cached size/sigops/fee values that are not actually correct.
bool BlockAssembler::SkipMapTxEntry(CTxMemPool::txiter it, indexed_modified_transaction_set &mapModifiedTx, CTxMemPool::setEntries &failedTx)
{
    assert(it != m_mempool.mapTx.end());
    return mapModifiedTx.count(it) || inBlock.count(it) || failedTx.count(it);
}

void BlockAssembler::SortForBlock(const CTxMemPool::setEntries& package, std::vector<CTxMemPool::txiter>& sortedEntries)
{
    // Sort package by ancestor count
    // If a transaction A depends on transaction B, then A's ancestor count
    // must be greater than B's.  So this is sufficient to validly order the
    // transactions for block inclusion.
    sortedEntries.clear();
    sortedEntries.insert(sortedEntries.begin(), package.begin(), package.end());
    std::sort(sortedEntries.begin(), sortedEntries.end(), CompareTxIterByAncestorCount());
}

// This transaction selection algorithm orders the mempool based
// on feerate of a transaction including all unconfirmed ancestors.
// Since we don't remove transactions from the mempool as we select them
// for block inclusion, we need an alternate method of updating the feerate
// of a transaction with its not-yet-selected ancestors as we go.
// This is accomplished by walking the in-mempool descendants of selected
// transactions and storing a temporary modified state in mapModifiedTxs.
// Each time through the loop, we compare the best transaction in
// mapModifiedTxs with the next transaction in the mempool to decide what
// transaction package to work on next.
void BlockAssembler::addPackageTxs(int &nPackagesSelected, int &nDescendantsUpdated)
{
    // mapModifiedTx will store sorted packages after they are modified
    // because some of their txs are already in the block
    indexed_modified_transaction_set mapModifiedTx;
    // Keep track of entries that failed inclusion, to avoid duplicate work
    CTxMemPool::setEntries failedTx;

    // Start by adding all descendants of previously added txs to mapModifiedTx
    // and modifying them for their already included ancestors
    UpdatePackagesForAdded(inBlock, mapModifiedTx);

    CTxMemPool::indexed_transaction_set::index<ancestor_score>::type::iterator mi = m_mempool.mapTx.get<ancestor_score>().begin();
    CTxMemPool::txiter iter;

    // Limit the number of attempts to add transactions to the block when it is
    // close to full; this is just a simple heuristic to finish quickly if the
    // mempool has a lot of entries.
    const int64_t MAX_CONSECUTIVE_FAILURES = 1000;
    int64_t nConsecutiveFailed = 0;

    while (mi != m_mempool.mapTx.get<ancestor_score>().end() || !mapModifiedTx.empty()) {
        // First try to find a new transaction in mapTx to evaluate.
        if (mi != m_mempool.mapTx.get<ancestor_score>().end() &&
            SkipMapTxEntry(m_mempool.mapTx.project<0>(mi), mapModifiedTx, failedTx)) {
            ++mi;
            continue;
        }

        // Now that mi is not stale, determine which transaction to evaluate:
        // the next entry from mapTx, or the best from mapModifiedTx?
        bool fUsingModified = false;

        modtxscoreiter modit = mapModifiedTx.get<ancestor_score>().begin();
        if (mi == m_mempool.mapTx.get<ancestor_score>().end()) {
            // We're out of entries in mapTx; use the entry from mapModifiedTx
            iter = modit->iter;
            fUsingModified = true;
        } else {
            // Try to compare the mapTx entry to the mapModifiedTx entry
            iter = m_mempool.mapTx.project<0>(mi);
            if (modit != mapModifiedTx.get<ancestor_score>().end() &&
                    CompareTxMemPoolEntryByAncestorFee()(*modit, CTxMemPoolModifiedEntry(iter))) {
                // The best entry in mapModifiedTx has higher score
                // than the one from mapTx.
                // Switch which transaction (package) to consider
                iter = modit->iter;
                fUsingModified = true;
            } else {
                // Either no entry in mapModifiedTx, or it's worse than mapTx.
                // Increment mi for the next loop iteration.
                ++mi;
            }
        }

        // We skip mapTx entries that are inBlock, and mapModifiedTx shouldn't
        // contain anything that is inBlock.
        assert(!inBlock.count(iter));

        uint64_t packageSize = iter->GetSizeWithAncestors();
        CAmount packageFees = iter->GetModFeesWithAncestors();
        int64_t packageSigOpsCost = iter->GetSigOpCostWithAncestors();
        if (fUsingModified) {
            packageSize = modit->nSizeWithAncestors;
            packageFees = modit->nModFeesWithAncestors;
            packageSigOpsCost = modit->nSigOpCostWithAncestors;
        }

        if (packageFees < blockMinFeeRate.GetFee(packageSize)) {
            // Everything else we might consider has a lower fee rate
            return;
        }

        if (!TestPackage(packageSize, packageSigOpsCost)) {
            if (fUsingModified) {
                // Since we always look at the best entry in mapModifiedTx,
                // we must erase failed entries so that we can consider the
                // next best entry on the next loop iteration
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }

            ++nConsecutiveFailed;

            if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES && nBlockWeight >
                    nBlockMaxWeight - 4000) {
                // Give up if we're close to full and haven't succeeded in a while
                break;
            }
            continue;
        }

        CTxMemPool::setEntries ancestors;
        uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
        std::string dummy;
        m_mempool.CalculateMemPoolAncestors(*iter, ancestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy, false);

        onlyUnconfirmed(ancestors);
        ancestors.insert(iter);

        // Test if all tx's are Final
        if (!TestPackageTransactions(ancestors)) {
            if (fUsingModified) {
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }
            continue;
        }

        // This transaction will make it in; reset the failed counter.
        nConsecutiveFailed = 0;

        // Package can be added. Sort the entries in a valid order.
        std::vector<CTxMemPool::txiter> sortedEntries;
        SortForBlock(ancestors, sortedEntries);

        for (size_t i=0; i<sortedEntries.size(); ++i) {
            AddToBlock(sortedEntries[i]);
            // Erase from the modified set, if present
            mapModifiedTx.erase(sortedEntries[i]);
        }

        ++nPackagesSelected;

        // Update transactions that depend on each of these
        nDescendantsUpdated += UpdatePackagesForAdded(ancestors, mapModifiedTx);
    }
}

void IncrementExtraNonce(CBlock* pblock, const CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2
    CMutableTransaction txCoinbase(*pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce));
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
}

static CScript GetFnNodePayee(int nHeight) {
    size_t size_ = fndata.size();
    int winner_index = nHeight % (size_ -1);
    return CScript() << OP_DUP << OP_HASH160 << ParseHex(fndata[winner_index].first) << OP_EQUALVERIFY << OP_CHECKSIG;
}

bool FillMasternodePayments(CMutableTransaction& mtx, const int nHeight, CAmount blockreward)
{
    bool bMasterNodePayment = false;
    CScript payee;
    size_t vout_size = mtx.vout.size();
    //CAmount total_value_out_ = blockreward;

    const CAmount total_value_out = blockreward;
    const CAmount nFnReward = GetFnReward(total_value_out);
    const CAmount nMasternodeReward = GetMasternodeReward(total_value_out);

    if (GetTimeMicros() > 1430465291){ //START_MASTERNODE_PAYMENTS = 1430465291
        bMasterNodePayment = true;
    }

    if(bMasterNodePayment) {
        bool hasPayment = true;
        //spork
        if(!masternodePayments.GetBlockPayee(nHeight, payee)){
            //no masternode detected
            CMasternode* winningNode = mnodeman.GetCurrentMasterNode(1);
            if(winningNode){
                payee = GetScriptForDestination(PKHash(winningNode->pubkey));
            } else {
                LogPrintf("FillMasternodePayments: Failed to detect masternode to pay\n");
                hasPayment = false;
            }
        }
        if(hasPayment){

            mtx.vout.resize(vout_size+2);


            //dummy fundamentalnode
            mtx.vout[vout_size].scriptPubKey = GetFnNodePayee(nHeight);
            mtx.vout[vout_size].nValue = nFnReward;
            //masternode
            mtx.vout[vout_size+1].scriptPubKey = payee;
            mtx.vout[vout_size+1].nValue = nMasternodeReward;

            // this should work, but will fail if friction value or rounding off values,
            // to make this work correctly, stake split is highly discourage
            CAmount remaining_amount = total_value_out - (nFnReward + nMasternodeReward);
            for ( size_t i = 1; i < vout_size; i++) {
                mtx.vout[i].nValue += remaining_amount / (vout_size - 1);
            }

            // Check if last index is of masternode
            CTxOut out_ = mtx.vout.back();
            if (out_.scriptPubKey != payee){
                LogPrintf("FillMasternodePayments: santy check failed , last index is not masternode\n");
                return false;
            }

            CTxDestination address1;
            ExtractDestination(payee, address1);

            LogPrintf("Masternode payment to %s\n", EncodeDestination(address1));
            return true;
        } else
        {
            //defaut masternode payment
            LogPrintf("FillMasternodePayments: Failed to detect masternode to pay, filling default \n");
            payee = CScript() << OP_DUP << OP_HASH160 << ParseHex("6e0921cae1e98d6415860e26a54f5ea7fb303997") << OP_EQUALVERIFY << OP_CHECKSIG;


            CAmount remaining_amount = total_value_out - (nFnReward + nMasternodeReward);
            for ( size_t i = 1; i < vout_size; i++) {
                mtx.vout[i].nValue += remaining_amount / (vout_size -1);
            }

            // first fn
            mtx.vout.push_back(CTxOut(nFnReward, GetFnNodePayee(nHeight)));
            // second mn
            mtx.vout.push_back(CTxOut(nMasternodeReward, payee));
            return true;
        }
    }
    return false;
}

void static ThreadStakeMinter(std::shared_ptr<CWallet> pwallet, CConnman* connman, CTxMemPool* mempool)
{
    LogPrintf("Starting vitae-stake thread ...\n");
    util::ThreadRename("vitae-stake-minter");
    bool fSynced = false;
    bool fForceStake = fForceStaking; // todo make this gArgs.GetBoolArgs("-fForceStake", "false") and extern fForceStake

    while(!fShutdownRequested) {
        if (pwallet->IsLocked() ||
                ((::ChainstateActive().IsInitialBlockDownload() ||
                !connman ||
                connman->GetNodeCount(CConnman::CONNECTIONS_ALL) < 3) && !fForceStake)) {
            stakestat = WAITING_TO_SYNC;
            UninterruptibleSleep(std::chrono::milliseconds{10000}); // retry after 10 seconds
            continue;
        }
        if (!::ChainstateActive().IsInitialBlockDownload())
            fSynced = true;

        if (!fSynced && !fForceStake)
            continue;

        if (fImporting || fReindex) {
            UninterruptibleSleep(std::chrono::milliseconds{3000}); // retry after 3 seconds
            continue;
        }


        if (fForceStake)
            LogPrintf("Force stake is true.\n");

        stakestat = ENABLED;

        /** Get the block template, the more efficient way is to find kernel first then make template -> block
         * But we end up with making template anyway, this is not efficient for small stakers
         */
        CScript dummyScript;
        std::unique_ptr<CBlockTemplate> pblocktemplate(BlockAssembler(*mempool, Params()).CreateNewBlock(dummyScript));

        if (!pblocktemplate) {
            //throw std::runtime_error(strprintf("%s: Failed to get blocktemplate", __func__));
            LogPrintf("Failed to get blocktemplate \n.");
            return;
        }
        CBlock *pblock = &pblocktemplate->block;
        CMutableTransaction mStakeTxn;
        CAmount nBlockReward = pblock->vtx[0]->vout[0].nValue;
        unsigned int nMintedBlockTime;
        int nBlockHeight = 0;
        if (!pwallet->CreateCoinStake(pblock->nBits, 0/*nBlockReward*/, mStakeTxn, nMintedBlockTime, true, nBlockHeight)) {
            UninterruptibleSleep(std::chrono::milliseconds{5000});
            continue;
        }
        //CreatedCoinStake successfully
        //!Next steps are
        //! fill masternode payments
        //! sign stake transaction
        //! remove coinbase payment as it is POS block
        //! sign the block
        //! broadcast signed block and ProcessNewBlock

        // Fill masternode and fundamentalnode
        {
            if (!FillMasternodePayments(mStakeTxn, nBlockHeight, nBlockReward)) {
                LogPrintf("ThreadStakeMinter : masternode is missing\n");
                UninterruptibleSleep(std::chrono::milliseconds{5000});
                continue;
            }
        }

        // sign stake txn
        {
            LOCK(pwallet->cs_wallet);
            if (!pwallet->SignTransaction(mStakeTxn))
                throw std::runtime_error(strprintf("%s: Failed to get Sign stake. ", __func__));
        }


        // remove coinbase as pow
        {
            LOCK(cs_main);
            CBlockIndex* pindexPrev = ::ChainActive().Tip();
            CMutableTransaction mutableTx(*pblock->vtx[0]);
            mutableTx.vout.clear();
            mutableTx.vout.resize(1);
            mutableTx.vout[0] = CTxOut(0, CScript());
            pblock->vtx[0] = MakeTransactionRef(std::move(mutableTx));
            pblock->vtx.insert(pblock->vtx.begin() + 1, MakeTransactionRef(std::move(mStakeTxn)));
            pblock->nTime = nMintedBlockTime;
            pblocktemplate->vchCoinbaseCommitment = GenerateCoinbaseCommitment(*pblock, pindexPrev, Params().GetConsensus());
            pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
        }
        // sign block
        {
            LOCK2(cs_main, pwallet->cs_wallet);
            if (!SignBlock(*pblock, *pwallet)) {
                throw std::runtime_error(strprintf("%s: Failed to Sign block. ", __func__));
            }
        }
        // broadcast it
        std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(*pblock);
        if (!ProcessNewBlock(Params(), shared_pblock, true, nullptr)) {
            LogPrintf("ThreadStakeMinter: ProcessNewBlock failed \n.");
            UninterruptibleSleep(std::chrono::milliseconds{10000});
            continue;
        }

        // rest
        UninterruptibleSleep(std::chrono::milliseconds{10000});
        continue;
    }

}

void StakeThreadMan(/*boost::thread_group& threadGroup,*/ std::shared_ptr<CWallet> pwallet, CConnman* connman, CTxMemPool* mempool)
{
    try
    {
        ThreadStakeMinter(pwallet, connman, mempool);
    }
    catch (boost::thread_interrupted)
    {
        LogPrintf("vitae-staker terminated\n");
        stakestat = DISABLED;
        return;
        // throw;
    }
    catch (const std::runtime_error &e)
    {
        LogPrintf("vitae-staker runtime error: %s\n", e.what());
        stakestat = DISABLED;
        return;
    }

    //threadGroup.create_thread(boost::bind(&ThreadStakeMinter, pwallet, connman, mempool, fShutdownRequest));

}
