
#include "net.h"
#include "netbase.h"
#include "masternodes/masternodeconfig.h"
#include "util/system.h"
#include <base58.h>
#include <util/strencodings.h>
#include <key_io.h>

CMasternodeConfig masternodeConfig;

void CMasternodeConfig::add(std::string alias, std::string ip, std::string privKey, std::string txHash, std::string outputIndex, std::string donationAddress, std::string donationPercent) {
    CMasternodeEntry cme(alias, ip, privKey, txHash, outputIndex, donationAddress, donationPercent);
    entries.push_back(cme);
}

bool CMasternodeConfig::read(std::string& strErr) {
    boost::filesystem::ifstream streamConfig(GetMasternodeConfigFile());
    if (!streamConfig.good()) {
        return true; // No masternode.conf file is OK
    }

    for(std::string line; std::getline(streamConfig, line); )
    {
        if(line.empty()) {
            continue;
        }
        std::istringstream iss(line);
        std::string alias, ip, privKey, txHash, outputIndex, donation, donationAddress, donationPercent;
        if (!(iss >> alias >> ip >> privKey >> txHash >> outputIndex >> donation)) {
            donationAddress = "";
            donationPercent = "";
            iss.str(line);
            iss.clear();
            if (!(iss >> alias >> ip >> privKey >> txHash >> outputIndex)) {
                strErr = "Could not parse masternode.conf line: " + line;
                streamConfig.close();
                return false;
            }
        } else {
            size_t pos = donation.find_first_of(":");
            if(pos == std::string::npos) { // no ":" found
                donationPercent = "100";
                donationAddress = donation;
            } else {
                donationPercent = donation.substr(pos + 1);
                donationAddress = donation.substr(0, pos);
            }
            //CBitsendAddress address(donationAddress);

            if (!IsValidDestinationString(donationAddress)) {
                strErr = "Invalid Vitae address in masternode.conf line: " + line;
                streamConfig.close();
                return false;
            }
        }
		
		int port = 0;
        std::string hostname = "";

		SplitHostPort(ip, port, hostname);
        
            if(port != 8765) {
                strErr = "Invalid port detected in masternode.conf: " + line + " (must be 8765 for mainnet)";
                streamConfig.close();
                return false;
            }
        


        add(alias, ip, privKey, txHash, outputIndex, donationAddress, donationPercent);
    }

    streamConfig.close();
    return true;
}
