

#include <validation.h>

#include <sync.h>
#include <masternodes/activemasternode.h>
#include <chainparams.h>
#include <key_io.h>




class CMNSignHelper{

public:
    CScript collateralPubKey;
    /// Is the inputs associated with this public key? (and there is 14000 BSD - checking if valid masternode)
    bool IsVinAssociatedWithPubkey(CTxIn& vin, CPubKey& pubkey, uint256& blockhash){
        CScript payee2;
        payee2=GetScriptForDestination(PKHash(pubkey));

        CTransactionRef txVin;
        //uint256 hash;
        if(GetTransaction(vin.prevout.hash, txVin, Params().GetConsensus(), blockhash, nullptr)){
            for (size_t i = 0; i < txVin->vout.size(); ++i){
                if(txVin->vout[i].nValue == MASTERNODEAMOUNT*COIN){
                    if(txVin->vout[i].scriptPubKey == payee2){
                        return true;
                    }
                }
            }
        } else{
            return false;
        }
        return false;
    }
    /// Set the private/public key values, returns true if successful
    bool SetKey(std::string strSecret, std::string& errorMessage, CKey& key, CPubKey& pubkey){
        CKey privkey = DecodeSecret(strSecret);

        if (!privkey.IsValid()) {
            errorMessage = ("Invalid private key.");
            return false;
        }

        key = privkey;//vchSecret.GetKey();
        pubkey = privkey.GetPubKey();

        return true;
    }

    /// Sign the message, returns true if successful
    bool SignMessage(std::string strMessage, std::string& errorMessage, vector<unsigned char>& vchSig, CKey key)
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss << MESSAGE_MAGIC;
        ss << strMessage;

        if (!key.SignCompact(ss.GetHash(), vchSig)) {
            errorMessage = ("Signing failed.");
            return false;
        }

        return true;
    }
    /// Verify the message, returns true if succcessful
    bool VerifyMessage(CPubKey pubkey, vector<unsigned char>& vchSig, std::string strMessage, std::string& errorMessage)
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss << MESSAGE_MAGIC;
        ss << strMessage;

        CPubKey pubkey2;
        if (!pubkey2.RecoverCompact(ss.GetHash(), vchSig)) {
            errorMessage = ("Error recovering public key.");
            return false;
        }

        if (/*fDebug &&*/ pubkey2.GetID() != pubkey.GetID())
            LogPrintf("CDarkSendSigner::VerifyMessage -- keys don't match: %s %s", pubkey2.GetID().ToString(), pubkey.GetID().ToString());

        return (pubkey2.GetID() == pubkey.GetID());
    }

    bool SetCollateralAddress(std::string strAddress){
        //CBitsendAddress address;
        CTxDestination dest = DecodeDestination(strAddress);
        if (!IsValidDestination(dest))
        {
            LogPrintf("CDarksendPool::SetCollateralAddress - Invalid Darksend collateral address\n");
            return false;
        }
        collateralPubKey = GetScriptForDestination(dest);
        return true;
    }
    void InitCollateralAddress(){
        std::string strAddress = "";
        
        strAddress = "Vk2eBKCCpwe2ah1HwryJ9pvHrTpeovFUh7";
        
        
        SetCollateralAddress(strAddress);
    }

};

void ThreadBitPool(CConnman *connman);



extern CMNSignHelper darkSendSigner;
extern std::string strMasterNodePrivKey;

