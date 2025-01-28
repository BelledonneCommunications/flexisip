/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <sstream>

#include "flexisip/logmanager.hh"

#include "iptables-executor.hh"

using namespace std;
using namespace flexisip;

int IptablesExecutor::runIptables(const std::string& arguments, bool ipv6, bool dumpErrors) {
	ostringstream command{};
	char output[512] = {0};

	command << (ipv6 ? "/sbin/ip6tables" : "/sbin/iptables");
	command << " " << arguments;
	command << " 2>&1";
	FILE* f = popen(command.str().c_str(), "r");
	if (f == nullptr) {
		LOGE << "popen() failed: " << strerror(errno);
		return -1;
	}
	size_t readCount = fread(output, 1, sizeof(output) - 1, f);
	int ret = pclose(f);
	if (WIFEXITED(ret)) ret = WEXITSTATUS(ret);
	if (ret != 0 && dumpErrors) {
		LOGE << "'" << command.str() << "' failed with output: " << output;
	}
	if (ret == 0 || !dumpErrors) LOGI << "'" << command.str() << "' successfully executed";
	(void)readCount; // This variable is useless here, I know.
	return ret;
}

void IptablesExecutor::onLoad(const flexisip::GenericStruct* dosModuleConfig) {
	mFlexisipChain = dosModuleConfig->get<ConfigString>("iptables-chain")->read();

	// Let's remove the Flexisip's chain in case the previous run crashed
	char iptables_cmd[512];

	if (runIptables("-w -V > /dev/null") == 0) {
		// iptables seems to support -w parameter required to allow concurrent usage of iptables
		mIptablesSupportsWait = true;
	}

	// First we have to empty the chain, for ipv4
	snprintf(iptables_cmd, sizeof(iptables_cmd), "%s -F %s", mIptablesSupportsWait ? "-w" : "", mFlexisipChain.c_str());
	if (runIptables(iptables_cmd) == 0) {
		// Then we have to remove the link to be able to remove the chain itself
		snprintf(iptables_cmd, sizeof(iptables_cmd), "%s -t filter -D INPUT -j %s", mIptablesSupportsWait ? "-w" : "",
		         mFlexisipChain.c_str());
		runIptables(iptables_cmd);

		snprintf(iptables_cmd, sizeof(iptables_cmd), "%s -X %s", mIptablesSupportsWait ? "-w" : "",
		         mFlexisipChain.c_str());
		runIptables(iptables_cmd);
	}
	// Same thing for IPv6
	snprintf(iptables_cmd, sizeof(iptables_cmd), "%s -F %s", mIptablesSupportsWait ? "-w" : "", mFlexisipChain.c_str());
	if (runIptables(iptables_cmd, true) == 0) {
		// Then we have to remove the link to be able to remove the chain itself
		snprintf(iptables_cmd, sizeof(iptables_cmd), "%s -t filter -D INPUT -j %s", mIptablesSupportsWait ? "-w" : "",
		         mFlexisipChain.c_str());
		runIptables(iptables_cmd, true);

		snprintf(iptables_cmd, sizeof(iptables_cmd), "%s -X %s", mIptablesSupportsWait ? "-w" : "",
		         mFlexisipChain.c_str());
		runIptables(iptables_cmd, true);
	}

	// Now let's create it
	snprintf(iptables_cmd, sizeof(iptables_cmd), "%s -N %s", mIptablesSupportsWait ? "-w" : "", mFlexisipChain.c_str());
	runIptables(iptables_cmd);
	runIptables(iptables_cmd, true);
	// Finally let's add a jump from the INPUT chain to ours
	snprintf(iptables_cmd, sizeof(iptables_cmd), "%s -t filter -A INPUT -j %s", mIptablesSupportsWait ? "-w" : "",
	         mFlexisipChain.c_str());
	runIptables(iptables_cmd);
	runIptables(iptables_cmd, true);
}

void IptablesExecutor::onUnload() {
	// Let's remove the Flexisip's chain
	char iptables_cmd[512];
	// First we have to empty the chain
	snprintf(iptables_cmd, sizeof(iptables_cmd), "%s -F %s", mIptablesSupportsWait ? "-w" : "", mFlexisipChain.c_str());
	runIptables(iptables_cmd);
	runIptables(iptables_cmd, true);

	// Then we have to remove the link to be able to remove the chain itself
	snprintf(iptables_cmd, sizeof(iptables_cmd), "%s -t filter -D INPUT -j %s", mIptablesSupportsWait ? "-w" : "",
	         mFlexisipChain.c_str());
	runIptables(iptables_cmd);
	runIptables(iptables_cmd, true);

	snprintf(iptables_cmd, sizeof(iptables_cmd), "%s -X %s", mIptablesSupportsWait ? "-w" : "", mFlexisipChain.c_str());
	runIptables(iptables_cmd);
	runIptables(iptables_cmd, true);
}

void IptablesExecutor::banIP(const string& ip, const string& port, const string& protocol) {
	char iptables_cmd[512];
	snprintf(iptables_cmd, sizeof(iptables_cmd), "%s -C %s -p %s -s %s -m multiport --sports %s -j REJECT",
	         mIptablesSupportsWait ? "-w" : "", mFlexisipChain.c_str(), protocol.c_str(), ip.c_str(), port.c_str());
	bool is_ipv6 = strchr(ip.c_str(), ':') != nullptr;
	if (runIptables(iptables_cmd, is_ipv6, false) == 0) {
		LOGI << "Skip " << ip << ":" << port << " on " << protocol << " as it is already in the iptables banned list";
	} else {
		snprintf(iptables_cmd, sizeof(iptables_cmd), "%s -A %s -p %s -s %s -m multiport --sports %s -j REJECT",
		         mIptablesSupportsWait ? "-w" : "", mFlexisipChain.c_str(), protocol.c_str(), ip.c_str(), port.c_str());
		runIptables(iptables_cmd, is_ipv6);
	}
}

void IptablesExecutor::unbanIP(const string& ip, const string& port, const string& protocol) {
	char iptables_cmd[512];
	bool is_ipv6 = strchr(ip.c_str(), ':') != nullptr;
	snprintf(iptables_cmd, sizeof(iptables_cmd), "%s -D %s -p %s -s %s -m multiport --sports %s -j REJECT",
	         mIptablesSupportsWait ? "-w" : "", mFlexisipChain.c_str(), protocol.c_str(), ip.c_str(), port.c_str());
	runIptables(iptables_cmd, is_ipv6);
}

void IptablesExecutor::checkConfig() {
	if (runIptables("-V > /dev/null", true) != 0)
		LOGW << "ip6tables command is not installed, DoS protection is inactive for IPv6";
}