// Copyright (c) 2014-2015 The Bitsend developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "masternodes/masternode.h"
#include "masternodeman.h"
#include "signhelper_mn.h"//todo++
//#include "core.h"
#include "util/system.h"
#include "sync.h"
#include "addrman.h"
#include "net.h"
#include "net_processing.h"
#include "consensus/validation.h"
#include <boost/lexical_cast.hpp>
#include <boost/foreach.hpp>

RecursiveMutex cs_masternodepayments;


/** Object for who's going to get paid on which blocks */
CMasternodePayments masternodePayments;
// keep track of Masternode votes I've seen
map<uint256, CMasternodePaymentWinner> mapSeenMasternodeVotes;
// keep track of the scanning errors I've seen
map<uint256, int> mapSeenMasternodeScanningErrors;
// cache block hashes as we calculate them
std::map<int64_t, uint256> mapCacheBlockHashes;

static void RelayMNpayments(CMasternodePaymentWinner& winner, CNode* pnode, CConnman* connman)
{
    CInv inv(MSG_MASTERNODE_WINNER, winner.GetHash());

    vector<CInv> vInv;
    vInv.push_back(inv);
    /*LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes){
        pnode->PushMessage("inv", vInv);
    }*/
        connman->ForEachNode([&vInv, connman](CNode* pnode)
    {
        connman->PushMessage(pnode, CNetMsgMaker(PROTOCOL_VERSION).Make(SERIALIZE_TRANSACTION_NO_WITNESS, "inv", vInv));
    });
}

void ProcessMessageMasternodePayments(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman* connman)
{
    if(::ChainstateActive().IsInitialBlockDownload()) return;

    if (strCommand == "mnget") { //Masternode Payments Request Sync
        //if(fProUserModeDarksendInstantX2) return; //disable all Darksend/Masternode related functionality

        if(pfrom->HasFulfilledRequest("mnget")) {
            LogPrintf("mnget - peer already asked me for the list\n");
            //Misbehaving(pfrom->GetId(), 20);
            return;
        }

        pfrom->FulfilledRequest("mnget");
        masternodePayments.Sync(pfrom, connman);
        LogPrintf("mnget - Sent Masternode winners to %s\n", pfrom->addr.ToString().c_str());
    }
    else if (strCommand == "mnw") { //Masternode Payments Declare Winner

        LOCK(cs_masternodepayments);

        //this is required in litemode
        CMasternodePaymentWinner winner;
        vRecv >> winner;

        if(::ChainActive().Tip() == NULL) return;

        CTxDestination address1;
        ExtractDestination(winner.payee, address1);
        //CBitsendAddress address2(address1);

        arith_uint256 hash = UintToArith256(winner.GetHash());
        if(mapSeenMasternodeVotes.count(ArithToUint256(hash))) {
            //if(fDebug) LogPrintf("mnw - seen vote %s Addr %s Height %d bestHeight %d\n", hash.ToString().c_str(), address2.ToString().c_str(), winner.nBlockHeight, ::ChainActive().Tip()->nHeight);
            return;
        }

        if(winner.nBlockHeight < ::ChainActive().Tip()->nHeight - 10 || winner.nBlockHeight > ::ChainActive().Tip()->nHeight+20){
            LogPrintf("mnw - winner out of range %s Addr %s Height %d bestHeight %d\n", winner.vin.ToString().c_str(), EncodeDestination(address1), winner.nBlockHeight, ::ChainActive().Tip()->nHeight);
            return;
        }

        if(winner.vin.nSequence != std::numeric_limits<unsigned int>::max()){
            LogPrintf("mnw - invalid nSequence\n");
            //Misbehaving(pfrom->GetId(), 100);
            return;
        }

        LogPrintf("mnw - winning vote - Vin %s Addr %s Height %d bestHeight %d\n", winner.vin.ToString().c_str(), EncodeDestination(address1), winner.nBlockHeight, ::ChainActive().Tip()->nHeight);

        if(!masternodePayments.CheckSignature(winner)){
            LogPrintf("mnw - invalid signature\n");
            //Misbehaving(pfrom->GetId(), 100);
            return;
        }

        mapSeenMasternodeVotes.insert(make_pair(ArithToUint256(hash), winner));

        if(masternodePayments.AddWinningMasternode(winner)){
			LogPrintf("mnw - \n");
            RelayMNpayments(winner, pfrom, connman);
        }
    }
}

struct CompareValueOnly
{
    bool operator()(const pair<int64_t, CTxIn>& t1,
                    const pair<int64_t, CTxIn>& t2) const
    {
        return t1.first < t2.first;
    }
};

//Get the last hash that matches the modulus given. Processed in reverse order
bool GetBlockHash(uint256& hash, int nBlockHeight)
{
    if (::ChainActive().Tip() == NULL) return false;

    if(nBlockHeight == 0)
        nBlockHeight = ::ChainActive().Tip()->nHeight;

    if(mapCacheBlockHashes.count(nBlockHeight)){
        hash = mapCacheBlockHashes[nBlockHeight];
        return true;
    }

    const CBlockIndex *BlockLastSolved = ::ChainActive().Tip();
    const CBlockIndex *BlockReading = ::ChainActive().Tip();

    if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || ::ChainActive().Tip()->nHeight+1 < nBlockHeight) return false;

    int nBlocksAgo = 0;
    if(nBlockHeight > 0) nBlocksAgo = (::ChainActive().Tip()->nHeight+1)-nBlockHeight;
    assert(nBlocksAgo >= 0);

    int n = 0;
    for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
        if(n >= nBlocksAgo){
            hash = BlockReading->GetBlockHash();
            mapCacheBlockHashes[nBlockHeight] = hash;
            return true;
        }
        n++;

        if (BlockReading->pprev == NULL) { assert(BlockReading); break; }
        BlockReading = BlockReading->pprev;
    }

    return false;
}

CMasternode::CMasternode()
{
    LOCK(cs);
    vin = CTxIn();
    addr = CService();
    pubkey = CPubKey();
    pubkey2 = CPubKey();
    sig = std::vector<unsigned char>();
    activeState = MASTERNODE_ENABLED;
    sigTime = GetAdjustedTime();
    lastDseep = 0;
    lastTimeSeen = 0;
    cacheInputAge = 0;
    cacheInputAgeBlock = 0;
    unitTest = false;
    allowFreeTx = true;
    protocolVersion = MIN_PEER_PROTO_VERSION;
    nLastDsq = 0;
    donationAddress = CScript();
    donationPercentage = 0;
    nVote = 0;
    lastVote = 0;
    nScanningErrorCount = 0;
    nLastScanningErrorBlockHeight = 0;
}

CMasternode::CMasternode(const CMasternode& other)
{
    LOCK(cs);
    vin = other.vin;
    addr = other.addr;
    pubkey = other.pubkey;
    pubkey2 = other.pubkey2;
    sig = other.sig;
    activeState = other.activeState;
    sigTime = other.sigTime;
    lastDseep = other.lastDseep;
    lastTimeSeen = other.lastTimeSeen;
    cacheInputAge = other.cacheInputAge;
    cacheInputAgeBlock = other.cacheInputAgeBlock;
    unitTest = other.unitTest;
    allowFreeTx = other.allowFreeTx;
    protocolVersion = other.protocolVersion;
    nLastDsq = other.nLastDsq;
    donationAddress = other.donationAddress;
    donationPercentage = other.donationPercentage;
    nVote = other.nVote;
    lastVote = other.lastVote;
    nScanningErrorCount = other.nScanningErrorCount;
    nLastScanningErrorBlockHeight = other.nLastScanningErrorBlockHeight;
}

CMasternode::CMasternode(CService newAddr, CTxIn newVin, CPubKey newPubkey, std::vector<unsigned char> newSig, int64_t newSigTime, CPubKey newPubkey2, int protocolVersionIn, CScript newDonationAddress, int newDonationPercentage)
{
    LOCK(cs);
    vin = newVin;
    addr = newAddr;
    pubkey = newPubkey;
    pubkey2 = newPubkey2;
    sig = newSig;
    activeState = MASTERNODE_ENABLED;
    sigTime = newSigTime;
    lastDseep = 0;
    lastTimeSeen = 0;
    cacheInputAge = 0;
    cacheInputAgeBlock = 0;
    unitTest = false;
    allowFreeTx = true;
    protocolVersion = protocolVersionIn;
    nLastDsq = 0;
    donationAddress = newDonationAddress;
    donationPercentage = newDonationPercentage;
    nVote = 0;
    lastVote = 0;
    nScanningErrorCount = 0;
    nLastScanningErrorBlockHeight = 0;
}

//
// Deterministically calculate a given "score" for a Masternode depending on how close it's hash is to
// the proof of work for that block. The further away they are the better, the furthest will win the election
// and get paid this block
//
uint256 CMasternode::CalculateScore(int mod, int64_t nBlockHeight)
{
    if(::ChainActive().Tip() == NULL) return ArithToUint256(0);

    uint256 hash = ArithToUint256(0);
    uint256 aux;
	aux = ArithToUint256(UintToArith256(vin.prevout.hash) + vin.prevout.n);

    if(!GetBlockHash(hash, nBlockHeight)) return ArithToUint256(0);

    uint256 hash2 = Hash(BEGIN(hash), END(hash));
    uint256 hash3 = Hash(BEGIN(hash), END(hash), BEGIN(aux), END(aux));

    arith_uint256 r;
	r = (UintToArith256(hash3) > UintToArith256(hash2) ? UintToArith256(hash3) - UintToArith256(hash2) : UintToArith256(hash2) - UintToArith256(hash3));

    return ArithToUint256(r);
}

void CMasternode::Check()
{
    //TODO: Random segfault with this line removed
    TRY_LOCK(cs_main, lockRecv);
    if(!lockRecv) return;

    if(nScanningErrorCount >= MASTERNODE_SCANNING_ERROR_THESHOLD)
    {
        activeState = MASTERNODE_POS_ERROR; // BBBBB
        return;
    }

    //once spent, stop doing the checks
    if(activeState == MASTERNODE_VIN_SPENT) return;


    if(!UpdatedWithin(MASTERNODE_REMOVAL_SECONDS)){
        activeState = MASTERNODE_REMOVE;
        return;
    }

    if(!UpdatedWithin(MASTERNODE_EXPIRATION_SECONDS)){
        activeState = MASTERNODE_EXPIRED;
        return;
    }

    if(!unitTest){
        TxValidationState state;
		CMutableTransaction mtx;
        CTxOut vout = CTxOut(4999.99*COIN, darkSendSigner.collateralPubKey);
        mtx.vin.push_back(vin);
        mtx.vout.push_back(vout);
		
        if(!AcceptableInputs(mempool, state, MakeTransactionRef(mtx))){
            activeState = MASTERNODE_VIN_SPENT;
			LogPrintf("tx failed to get accepted on mempool");
            return;
        } 
		
    }
	return;

    activeState = MASTERNODE_ENABLED; // OK
}

bool CMasternodePayments::CheckSignature(CMasternodePaymentWinner& winner)
{
    //note: need to investigate why this is failing
    std::string strMessage = winner.vin.ToString().c_str() + boost::lexical_cast<std::string>(winner.nBlockHeight) + HexStr(winner.payee);
    std::string strPubKey = (Params().NetworkIDString() == "main") ? strMainPubKey : strTestPubKey;
    CPubKey pubkey(ParseHex(strPubKey));

    std::string errorMessage = "";
    if(!darkSendSigner.VerifyMessage(pubkey, winner.vchSig, strMessage, errorMessage)){
        return false;
    }

    return true;
}

bool CMasternodePayments::Sign(CMasternodePaymentWinner& winner)
{
    std::string strMessage = winner.vin.ToString().c_str() + boost::lexical_cast<std::string>(winner.nBlockHeight) + HexStr(winner.payee);

    CKey key2;
    CPubKey pubkey2;
    std::string errorMessage = "";

    if(!darkSendSigner.SetKey(strMasterPrivKey, errorMessage, key2, pubkey2))
    {
        LogPrintf("CMasternodePayments::Sign - ERROR: Invalid Masternodeprivkey: '%s'\n", errorMessage.c_str());
        return false;
    }

    if(!darkSendSigner.SignMessage(strMessage, errorMessage, winner.vchSig, key2)) {
        LogPrintf("CMasternodePayments::Sign - Sign message failed");
        return false;
    }

    if(!darkSendSigner.VerifyMessage(pubkey2, winner.vchSig, strMessage, errorMessage)) {
        LogPrintf("CMasternodePayments::Sign - Verify message failed");
        return false;
    }

    return true;
}


uint64_t CMasternodePayments::CalculateScore(uint256 blockHash, CTxIn& vin)
{
    //BitSendDev & Joshafest 26-06-2016
    uint256 n1 = blockHash;
    uint256 n2, n3; arith_uint256 n4;
    {
        n2 = Hash(BEGIN(n1), END(n1));
        n3 = Hash(BEGIN(vin.prevout.hash), END(vin.prevout.hash));
        n4 = UintToArith256(n3) > UintToArith256(n2) ? (UintToArith256(n3) - UintToArith256(n2)) : (UintToArith256(n2) - UintToArith256(n3));
        return n4.Get64();
    }

    //printf(" -- CMasternodePayments CalculateScore() n2 = %d \n", n2.Get64());
    //printf(" -- CMasternodePayments CalculateScore() n3 = %d \n", n3.Get64());
    //printf(" -- CMasternodePayments CalculateScore() n4 = %d \n", n4.Get64());

}

bool CMasternodePayments::GetBlockPayee(int nBlockHeight, CScript& payee)
{
    BOOST_FOREACH(CMasternodePaymentWinner& winner, vWinning){
        if(winner.nBlockHeight == nBlockHeight) {
            payee = winner.payee;
            return true;
        }
    }

    return false;
}

bool CMasternodePayments::GetWinningMasternode(int nBlockHeight, CTxIn& vinOut)
{
    BOOST_FOREACH(CMasternodePaymentWinner& winner, vWinning){
        if(winner.nBlockHeight == nBlockHeight) {
            vinOut = winner.vin;
            return true;
        }
    }

    return false;
}

bool CMasternodePayments::AddWinningMasternode(CMasternodePaymentWinner& winnerIn)
{
    uint256 blockHash = uint256();
	//UintToArith256(blockHash) = 0;
    if(!GetBlockHash(blockHash, winnerIn.nBlockHeight-576)) {
        return false;
    }

    winnerIn.score = CalculateScore(blockHash, winnerIn.vin);

    bool foundBlock = false;
    BOOST_FOREACH(CMasternodePaymentWinner& winner, vWinning){
        if(winner.nBlockHeight == winnerIn.nBlockHeight) {
            foundBlock = true;
            if(winner.score < winnerIn.score){
                winner.score = winnerIn.score;
                winner.vin = winnerIn.vin;
                winner.payee = winnerIn.payee;
                winner.vchSig = winnerIn.vchSig;

                mapSeenMasternodeVotes.insert(make_pair(winnerIn.GetHash(), winnerIn));

                return true;
            }
        }
    }

    // if it's not in the vector
    if(!foundBlock){
        vWinning.push_back(winnerIn);
        mapSeenMasternodeVotes.insert(make_pair(winnerIn.GetHash(), winnerIn));

        return true;
    }

    return false;
}

void CMasternodePayments::CleanPaymentList()
{
    LOCK(cs_masternodepayments);

    if(::ChainActive().Tip() == NULL) return;

    int nLimit = std::max(((int)mnodeman.size())*2, 1000);

    vector<CMasternodePaymentWinner>::iterator it;
    for(it=vWinning.begin();it<vWinning.end();it++){
        if(::ChainActive().Tip()->nHeight - (*it).nBlockHeight > nLimit){
            //if(fDebug) LogPrintf("CMasternodePayments::CleanPaymentList - Removing old Masternode payment - block %d\n", (*it).nBlockHeight);
            vWinning.erase(it);
            break;
        }
    }
}

bool CMasternodePayments::ProcessBlock(int nBlockHeight)
{
    LOCK(cs_masternodepayments);
	
	LogPrintf(" CMasternodePayments::ProcessBlock running \n");

    if(nBlockHeight <= nLastBlockHeight){
		LogPrintf(" error::nBlockHeight <= nLastBlockHeight %d. \n", nBlockHeight);
		return false;}
    if(!enabled){ 
	    //LogPrintf(" error::notenabled");
	return false;
	}
    CMasternodePaymentWinner newWinner;
    int nMinimumAge = mnodeman.CountEnabled();
    CScript payeeSource;

    uint256 hash;
    if(!GetBlockHash(hash, nBlockHeight-10)){LogPrintf(" error::GetBlockHash(hash, nBlockHeight-10)");
		return false;
	}
    unsigned int nHash;
    memcpy(&nHash, &hash, 2);

    LogPrintf(" ProcessBlock Start nHeight %d. \n", nBlockHeight);

    std::vector<CTxIn> vecLastPayments;
    BOOST_REVERSE_FOREACH(CMasternodePaymentWinner& winner, vWinning)
    {
        //if we already have the same vin - we have one full payment cycle, break
       if(vecLastPayments.size() > nMinimumAge) break;
        vecLastPayments.push_back(winner.vin);
    }

    // pay to the oldest MN that still had no payment but its input is old enough and it was active long enough
    CMasternode *pmn = mnodeman.FindOldestNotInVec(vecLastPayments, nMinimumAge, 0);
    if(pmn != NULL)
    {
        LogPrintf(" Found by FindOldestNotInVec \n");
        
        newWinner.score = 0;
        newWinner.nBlockHeight = nBlockHeight;
        newWinner.vin = pmn->vin;

        if(pmn->donationPercentage > 0 && (nHash % 100) <= (unsigned int)pmn->donationPercentage) {
            newWinner.payee = pmn->donationAddress;
        } else {
            newWinner.payee=GetScriptForDestination(PKHash(pmn->pubkey));
        }
        
        payeeSource=GetScriptForDestination(PKHash(pmn->pubkey));
    }

    //if we can't find new MN to get paid, pick first active MN counting back from the end of vecLastPayments list
    if(newWinner.nBlockHeight == 0 && nMinimumAge > 0)
    {
        LogPrintf(" Find by reverse \n");
        BOOST_REVERSE_FOREACH(CTxIn& vinLP, vecLastPayments)
        {
            CMasternode* pmn = mnodeman.Find(vinLP);
            if(pmn != NULL)
            {
                pmn->Check();
                if(!pmn->IsEnabled()) continue;

                newWinner.score = 0;
                newWinner.nBlockHeight = nBlockHeight;
                newWinner.vin = pmn->vin;

                if(pmn->donationPercentage > 0 && (nHash % 100) <= (unsigned int)pmn->donationPercentage) {
                    newWinner.payee = pmn->donationAddress;
                } else {
                    newWinner.payee=GetScriptForDestination(PKHash(pmn->pubkey));
                }
                payeeSource=GetScriptForDestination(PKHash(pmn->pubkey));
                
                break; // we found active MN
            }
        }
    }

    if(newWinner.nBlockHeight == 0) return false;

    CTxDestination address1;
    ExtractDestination(newWinner.payee, address1);
    //CBitsendAddress address2(address1);

	CTxDestination address3;


	ExtractDestination(payeeSource, address3);
        //CBitsendAddress address4(address3);
        LogPrintf("Winner payee %s nHeight %d vin source %s. \n", EncodeDestination(address1), newWinner.nBlockHeight, EncodeDestination(address3) );

    if(Sign(newWinner))
    {
        if(AddWinningMasternode(newWinner))
        {
            Relay(newWinner);//todo ++ must add
            nLastBlockHeight = nBlockHeight;
            return true;
        }
    }

    return false;
}

void CMasternodePayments::Relay(CMasternodePaymentWinner& winner)
{
    CInv inv(MSG_MASTERNODE_WINNER, winner.GetHash());

    vector<CInv> vInv;
    vInv.push_back(inv);
    /*LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes){
        pnode->PushMessage("inv", vInv);
    }*/
        g_mn_node->connman->ForEachNode([&vInv](CNode* pnode)
    {
        g_mn_node->connman->PushMessage(pnode, CNetMsgMaker(PROTOCOL_VERSION).Make(SERIALIZE_TRANSACTION_NO_WITNESS, "inv", vInv));
    });
}

void CMasternodePayments::Sync(CNode* node, CConnman *connman)
{
    LOCK(cs_masternodepayments);

    BOOST_FOREACH(CMasternodePaymentWinner& winner, vWinning)
        if(winner.nBlockHeight >= ::ChainActive().Tip()->nHeight-10 && winner.nBlockHeight <= ::ChainActive().Tip()->nHeight + 20)
            connman->PushMessage(node, CNetMsgMaker(PROTOCOL_VERSION).Make(SERIALIZE_TRANSACTION_NO_WITNESS, "mnw", winner));//node->PushMessage("mnw", winner);
		
}


bool CMasternodePayments::SetPrivKey(std::string strPrivKey)
{
    CMasternodePaymentWinner winner;

    // Test signing successful, proceed
    strMasterPrivKey = strPrivKey;

    Sign(winner);

    if(CheckSignature(winner)){
        LogPrintf("CMasternodePayments::SetPrivKey - Successfully initialized as Masternode payments master\n");
        enabled = true;
        return true;
    } else {
        return false;
    }
}

NodeContext* g_mn_node = nullptr;
