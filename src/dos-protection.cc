/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2010  Belledonne Communications SARL.

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as
 published by the Free Software Foundation, either version 3 of the
 License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "flexisip-config.h"
#endif
#include "dos-protection.hh"
#include "configmanager.hh"
#include <unistd.h>
#include <stdio.h>
#include <iostream>
#include <stdlib.h>

#define CHECK_RETURN(return_val, cmd) 			\
	if(return_val != 0) { 				\
		LOGW("%s returns %d", cmd, return_val);	\
	}

DosProtection *DosProtection::sInstance = NULL;

using namespace ::std;

ConfigItemDescriptor items[] = { { Boolean, "enabled", "Enable or disable DOS protection using IPTables firewall.", "true" }, { StringList, "authorized-ip", "List of whitelist IPs which won't be affected by DOS protection.", "127.0.0.1" }, { Integer, "ban-duration",
		"Time (in seconds) while an IP have to not send any packet in order to leave the blacklist.", "60" }, { Integer, "packets-limit", "Number of packets authorized in 1sec before considering them as DOS attack.", "20" }, { Integer, "maximum-connections",
		"Maximal amount of simultaneous connections to accept.", "1000" }, config_item_end };

DosProtection::DosProtection() {
	ConfigStruct *s = new ConfigStruct("dos-protection", "DOS protection parameters.");
	s->addChildrenValues(items);
	ConfigManager::get()->getRoot()->addChild(s);
	mLoaded = false;
}

DosProtection::~DosProtection() {
	delete sInstance;
}

DosProtection *DosProtection::get() {
	if (sInstance == NULL) {
		sInstance = new DosProtection();
	}
	return sInstance;
}

bool directoryExists(const char* path)
{
  return (access(path, 00) == 0);
}

void DosProtection::load() {
	ConfigStruct *dosProtection = ConfigManager::get()->getRoot()->get<ConfigStruct>("dos-protection");
	mEnabled = dosProtection->get<ConfigBoolean>("enabled")->read();
	mAuthorizedIPs = dosProtection->get<ConfigStringList>("authorized-ip")->read();
	mBanDuration = dosProtection->get<ConfigInt>("ban-duration")->read();
	mPacketsLimit = dosProtection->get<ConfigInt>("packets-limit")->read();
	mMaximumConnections = dosProtection->get<ConfigInt>("maximum-connections")->read();

	mPort = 5060;
	mBlacklistMax = 200;
	mPeriod = 1;
	mLogLevel = "warning";
	mLogPrefix = "Flexisip-DOS";
	mFlexisipChain = "FLEXISIP";
	mBlacklistChain = "FLEXISIP_BLACKLIST";
	mCounterlist = "FLEXISIP_COUNTER";
	mPath = "/sbin/iptables";
	mRecentDirectoryName = NULL;
	mLoaded = true;
}

/* Uninstall IPTables firewall rules */
void DosProtection::stop() {
	if (!mLoaded) {
		load();
	}

	if (!mEnabled) {
		return;
	}

	if (getuid() != 0) {
		LOGE("Flexisip not started with root privileges! Can't add DOS protection iptables rules");
		return;
	}

	char cmd[100] = { 0 };
	int returnedValue;

	/* Restore previous state of IPtables */
	snprintf(cmd, sizeof(cmd)-1, "%s-restore < "CONFIG_DIR"/iptables.bak", mPath);
	returnedValue = system(cmd);
	CHECK_RETURN(returnedValue, cmd)

	/*
	 Removing SIP packets routing from INPUT to FLEXISIP chain's route
	 snprintf(cmd, sizeof(cmd)-1, "%s -D INPUT -p tcp --dport %i -j %s", mPath, mPort, mFlexisipChain);
	 returnedValue = system(cmd);
	 snprintf(cmd, sizeof(cmd)-1, "%s -D INPUT -p udp --dport %i -j %s", mPath, mPort, mFlexisipChain);
	 returnedValue = system(cmd);

	 Removing FLEXISIP chain
	 snprintf(cmd, sizeof(cmd)-1, "%s -F %s ", mPath, mFlexisipChain);
	 returnedValue = system(cmd);
	 snprintf(cmd, sizeof(cmd)-1, "%s -X %s ", mPath, mFlexisipChain);
	 returnedValue = system(cmd);

	 Removing BLACKLIST chain *
	 snprintf(cmd, sizeof(cmd)-1, "%s -F %s ", mPath, mBlacklistChain);
	 returnedValue = system(cmd);
	 snprintf(cmd, sizeof(cmd)-1, "%s -X %s ", mPath, mBlacklistChain);
	 returnedValue = system(cmd);
	 */
}

/* Install IPTables firewall rules */
void DosProtection::start() {
	if (!mLoaded) {
		load();
	}

	if (!mEnabled) {
		return;
	}

	if (getuid() != 0) {
		LOGE("Flexisip not started with root privileges! Can't remove DOS protection iptables rules");
		return;
	}

	char cmd[300];
	int returnedValue;

	/* Backup existing IPTables rules to restore this state after closing flexisip  */
	snprintf(cmd, sizeof(cmd)-1, "%s-save > "CONFIG_DIR"/iptables.bak", mPath);
	returnedValue = system(cmd);
	CHECK_RETURN(returnedValue, cmd)

	/* FLEXISIP chain */
	snprintf(cmd, sizeof(cmd) - 1, "%s -N %s", mPath, mFlexisipChain);
	returnedValue = system(cmd);
	CHECK_RETURN(returnedValue, cmd)

	/* Allowing some IPs to not be filtered by this rules */
	for (list<string>::const_iterator iterator = mAuthorizedIPs.begin(); iterator != mAuthorizedIPs.end(); ++iterator) {
		const char* ip = (*iterator).c_str();
		snprintf(cmd, sizeof(cmd) - 1, "%s -A %s -s %s -j ACCEPT", mPath, mFlexisipChain, ip);
		returnedValue = system(cmd);
		CHECK_RETURN(returnedValue, cmd)
	}

	/* BLACKLIST chain */
	snprintf(cmd, sizeof(cmd) - 1, "%s -N %s", mPath, mBlacklistChain);
	returnedValue = system(cmd);
	CHECK_RETURN(returnedValue, cmd)

	/* Logging blacklisted IPs */
	snprintf(cmd, sizeof(cmd) - 1, "%s -A %s -j LOG --log-prefix %s --log-level %s", mPath, mBlacklistChain, mLogPrefix, mLogLevel);
	returnedValue = system(cmd);
	CHECK_RETURN(returnedValue, cmd)

	/* Dropping packets from BLACKLIST chain and theirs IPs to BLACKLIST list */
	snprintf(cmd, sizeof(cmd) - 1, "%s -A %s -m recent --name %s --set -j DROP", mPath, mBlacklistChain, mBlacklistChain);
	returnedValue = system(cmd);
	CHECK_RETURN(returnedValue, cmd)

	/* Limitting the amount of simultaneous connections */
	snprintf(cmd, sizeof(cmd) - 1, "%s -A %s -m connlimit --connlimit-above %i -j DROP", mPath, mFlexisipChain, mMaximumConnections);
	returnedValue = system(cmd);
	CHECK_RETURN(returnedValue, cmd)

	/*
	 * We block all packets for a given duration
	 * If a packet arrives during this time, timer is reset to 0
	 * To change this behaviour to block packets for a duration without reseting timer to 0, replace --update by --rcheck
	 */
	snprintf(cmd, sizeof(cmd) - 1, "%s -A %s -m recent --update --name %s --seconds %i --rttl -j DROP", mPath, mFlexisipChain, mBlacklistChain, mBanDuration);
	returnedValue = system(cmd);
	CHECK_RETURN(returnedValue, cmd)

	/* Adding all incoming packets to COUNTER list */
	snprintf(cmd, sizeof(cmd) - 1, "%s -A %s -m state --state NEW -m recent --name %s --set", mPath, mFlexisipChain, mCounterlist);
	returnedValue = system(cmd);
	CHECK_RETURN(returnedValue, cmd)

	/* If limit of packets/seconds is reached into COUNTER list, we move the packet to the BLACKLIST chain */
	snprintf(cmd, sizeof(cmd) - 1, "%s -A %s -m state --state NEW -m recent --name %s --update --seconds %i --hitcount %i --rttl -j %s", mPath, mFlexisipChain, mCounterlist, mPeriod, mPacketsLimit, mBlacklistChain);
	returnedValue = system(cmd);
	CHECK_RETURN(returnedValue, cmd)

	/* If a packet purged it's sentence, we unblacklist it */
	snprintf(cmd, sizeof(cmd) - 1, "%s -A %s -m recent --name %s --remove -j ACCEPT", mPath, mFlexisipChain, mBlacklistChain);
	returnedValue = system(cmd);
	CHECK_RETURN(returnedValue, cmd)

	/* Routing all tcp/udp SIP traffic to FLEXISIP chain */
	snprintf(cmd, sizeof(cmd) - 1, "%s -A INPUT -p tcp --dport %i -j %s", mPath, mPort, mFlexisipChain);
	returnedValue = system(cmd);
	CHECK_RETURN(returnedValue, cmd)
	snprintf(cmd, sizeof(cmd) - 1, "%s -A INPUT -p udp --dport %i -j %s", mPath, mPort, mFlexisipChain);
	returnedValue = system(cmd);
	CHECK_RETURN(returnedValue, cmd)

	/* Test recent module directory existence */
	if (mRecentDirectoryName == NULL) {
		const char* path_centos_6 = "/sys/module/xt_recent/";
		const char* path_centos_5 = "/sys/module/ipt_recent/";
		if (directoryExists(path_centos_5))
			mRecentDirectoryName = "ipt_recent";
		else if (directoryExists(path_centos_6))
			mRecentDirectoryName = "xt_recent";
	}

	/* Increasing recent module default values */
	snprintf(cmd, sizeof(cmd) - 1, "chmod u+w /sys/module/%s/parameters/ip_list_tot && echo %i > /sys/module/%s/parameters/ip_list_tot && chmod u-w /sys/module/%s/parameters/ip_list_tot", mRecentDirectoryName, mMaximumConnections, mRecentDirectoryName, mRecentDirectoryName);
	returnedValue = system(cmd);
	CHECK_RETURN(returnedValue, cmd)
	snprintf(cmd, sizeof(cmd) - 1, "chmod u+w /sys/module/%s/parameters/ip_pkt_list_tot && echo %i > /sys/module/%s/parameters/ip_pkt_list_tot && chmod u-w /sys/module/%s/parameters/ip_pkt_list_tot", mRecentDirectoryName, mBlacklistMax, mRecentDirectoryName, mRecentDirectoryName);
	returnedValue = system(cmd);
	CHECK_RETURN(returnedValue, cmd)
}
