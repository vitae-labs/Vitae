#include "signhelper_mn.h"
#include "masternodes/masternodeman.h"
#include "masternodes/masternode.h"
#include <util/threadnames.h>
#include <util/time.h>

#include <shutdown.h>
/*
Global
*/
//int RequestedMasterNodeList = 0;


void ThreadBitPool(CConnman* connman)
{

    // Make this thread recognisable as the wallet flushing thread
    util::ThreadRename("vitae-bitpool");
    LogPrintf("thread bitpool started\n");
    unsigned int c = 0;
    std::string errorMessage;

    while (!ShutdownRequested() /*&& !fReindex && !fImporting*/)
    {
        UninterruptibleSleep(std::chrono::milliseconds{1000});

        if (fReindex || fImporting) {
            UninterruptibleSleep(std::chrono::milliseconds{1000});
            continue;
        }

        if (::ChainstateActive().IsInitialBlockDownload())
            continue;

        if (!connman /*|| connman->GetNodeCount(CConnman::CONNECTIONS_ALL) == 0*/) {
            UninterruptibleSleep(std::chrono::milliseconds{3000});
            continue;
        }
        if (connman->GetNodeCount(CConnman::CONNECTIONS_ALL) == 0) {
            UninterruptibleSleep(std::chrono::milliseconds{3000});
            continue;
        }

        if(c % 60 == 0)
        {
            {
                LOCK(cs_main);
                /*
                    cs_main is required for doing CMasternode.Check because something
                    is modifying the coins view without a mempool lock. It causes
                    segfaults from this code without the cs_main lock.
                */
                mnodeman.CheckAndRemove();
                //mnodeman.ProcessMasternodeConnections();
                masternodePayments.CleanPaymentList();
            }

        }

        if(c % MASTERNODE_PING_SECONDS == 0) activeMasternode.ManageStatus();

        if(c % MASTERNODES_DUMP_SECONDS == 0) { DumpMasternodes(); c = 0;}

        c++;
        continue;
    }

    LogPrintf("thread bitpool terminated\n");
}
