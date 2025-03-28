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

#include "flexisip/dos/module-dos.hh"

#include <set>
#include <unordered_map>

#include "sofia-sip/msg_addr.h"
#include "sofia-sip/tport.h"

#include "flexisip/logmanager.hh"
#include "flexisip/module.hh"

#include "agent.hh"
#include "dos-executor/iptables-executor.hh"
#include "exceptions/bad-configuration.hh"
#include "utils/thread/basic-thread-pool.hh"

using namespace std;
using namespace flexisip;

ModuleInfo<ModuleDoSProtection> ModuleDoSProtection::sInfo(
    "DoSProtection",
    "Ban users when they send too much packets within a given timeframe. Execute \"iptables -L\" to see the list of "
    "currently banned IPs/ports.",
    {""},
    ModuleInfoBase::ModuleOid::DoSProtection,
    [](GenericStruct& moduleConfig) {
	    ConfigItemDescriptor configs[] = {
	        {
	            DurationMS,
	            "time-period",
	            "Time to consider to compute the packet rate",
	            "3000",
	        },
	        {
	            Integer,
	            "packet-rate-limit",
	            "Maximum packet rate in packets/seconds, averaged over [time-period] millisecond(s) to consider it as "
	            "a DoS attack.",
	            "20",
	        },
	        {
	            DurationMIN,
	            "ban-time",
	            "Time duration for which an ip/port is banned.",
	            "2",
	        },
	        {
	            String,
	            "iptables-chain",
	            "Name of the chain the server will create to store banned IPs",
	            "FLEXISIP",
	        },
	        {
	            StringList,
	            "white-list",
	            "List of IP addresses or hostnames for which no DoS protection is applied. This is typically for "
	            "trusted servers from which it is planned to receive high traffic. Please note that nodes from the "
	            "local Flexisip cluster (see [cluster] section) are automatically added to the white list, as well as "
	            "127.0.0.1 and ::1.\n"
	            "Example:\n"
	            "white-list=sip.example.org sip.linphone.org 15.128.128.93",
	            "",
	        },
	        config_item_end,
	    };
	    moduleConfig.get<ConfigBoolean>("enabled")->setDefault("true");
	    moduleConfig.addChildrenValues(configs);
    });

ModuleDoSProtection::ModuleDoSProtection(Agent* ag, ModuleInfoBase* moduleInfo) : Module(ag, moduleInfo) {
	mThreadPool = std::make_unique<BasicThreadPool>(1, 1000);
	mBanExecutor = std::make_shared<IptablesExecutor>();
}

void ModuleDoSProtection::onLoad(const GenericStruct* mc) {
	mTimePeriod = mc->get<ConfigDuration<chrono::milliseconds>>("time-period")->read().count();
	mPacketRateLimit = mc->get<ConfigInt>("packet-rate-limit")->read();
	mBanTime =
	    chrono::duration_cast<chrono::minutes>(mc->get<ConfigDuration<chrono::minutes>>("ban-time")->read()).count();
	mDOSHashtableIterator = mDosContexts.begin();

	GenericStruct* cluster = getAgent()->getConfigManager().getRoot()->get<GenericStruct>("cluster");
	list<string> whiteList = cluster->get<ConfigStringList>("nodes")->read();
	whiteList.splice(whiteList.end(), mc->get<ConfigStringList>("white-list")->read());

	LOGI << "Addresses 127.0.0.1 and ::1 automatically added to the white list";
	whiteList.push_back("127.0.0.1");
	whiteList.push_back("::1");
	for (auto it = whiteList.begin(); it != whiteList.end(); ++it) {
		const char* white_ip = (*it).c_str();
		LOGI << "Host " << white_ip << " is in white list";
		BinaryIp::emplace(mWhiteList, white_ip);
	}

	tport_t* primaries = tport_primaries(nta_agent_tports(mAgent->getSofiaAgent()));
	if (primaries == NULL) throw BadConfiguration{"no SIP transport defined"};
	for (tport_t* tport = primaries; tport != NULL; tport = tport_next(tport)) {
		tport_set_params(tport, TPTAG_DOS(mTimePeriod), TAG_END());
	}
	if (getuid() != 0) {
		LOGW << "Flexisip not started with root privileges: iptables commands for DoS protection will not work";
		return;
	}

	mBanExecutor->onLoad(mc);
}

void ModuleDoSProtection::onUnload() {
	mBanExecutor->onUnload();
}

bool ModuleDoSProtection::isValidNextConfig(const ConfigValue& value) {
	GenericStruct* module_config = dynamic_cast<GenericStruct*>(value.getParent());
	if (!module_config->get<ConfigBoolean>("enabled")->readNext()) return true;
	else {
#if __APPLE__
		module_config->get<ConfigBoolean>("enabled")->set("false");
		mExecutorConfigChecked = true; // unused-private-field if not set
		LOGW << "This module only works on linux hosts, disabling";
		return true;
#else
		if (!mExecutorConfigChecked) {
			mExecutorConfigChecked = true;
			mBanExecutor->checkConfig();
		}
		return true;
#endif
	}
}

void ModuleDoSProtection::onIdle() {
	struct timeval now;
	double started_time_in_millis, time_elapsed;

	gettimeofday(&now, NULL);
	started_time_in_millis = now.tv_sec * 1000 + (now.tv_usec / 1000);

	if (mDOSHashtableIterator == mDosContexts.end()) {
		mDOSHashtableIterator = mDosContexts.begin();
	}
	for (; mDOSHashtableIterator != mDosContexts.end();) {
		double now_in_millis;
		DosContext dos = mDOSHashtableIterator->second;

		gettimeofday(&now, NULL);
		now_in_millis = now.tv_sec * 1000 + (now.tv_usec / 1000);
		time_elapsed = now_in_millis - dos.last_check_recv_msg_check_time;

		if (time_elapsed >= 3600 * 1000) { // If no message received in the past hour
			mDOSHashtableIterator = mDosContexts.erase(mDOSHashtableIterator);
		} else {
			++mDOSHashtableIterator;
		}

		if (now_in_millis - started_time_in_millis >= 100) { // Do not use more than 100ms to clean the hashtable
			LOGW << "Started to clean hashtable " << (now_in_millis - started_time_in_millis)
			     << "ms ago, stop for now and continue later";
			break;
		}
	}
}

bool ModuleDoSProtection::isIpWhiteListed(const char* ip) {
	if (!ip) return true; // If IP is null, is useless to try to add it in iptables...
	return mWhiteList.find(BinaryIp(ip)) != mWhiteList.end();
}

void ModuleDoSProtection::unbanIP(const std::string& ip, const std::string& port, const std::string& protocol) {
	mThreadPool->run([this, protocol, ip, port] { mBanExecutor->unbanIP(ip, port, protocol); });
}

void ModuleDoSProtection::registerUnbanTimer(const string& ip, const string& port, const string& protocol) {
	mAgent->getRoot()->addOneShotTimer([this, ip, port, protocol]() { unbanIP(ip, port, protocol); },
	                                   chrono::minutes{mBanTime});
}

unique_ptr<RequestSipEvent> ModuleDoSProtection::onRequest(unique_ptr<RequestSipEvent>&& ev) {
	shared_ptr<tport_t> inTport = ev->getIncomingTport();
	tport_t* tport = inTport.get();

	if (tport == NULL) {
		LOGD << "Tport is null, cannot check the packet count rate";
		return std::move(ev);
	}

	if (tport_is_udp(tport)) { // Sofia doesn't create a secondary tport for udp, so it will ban the primary and we
		                       // don't want that
		shared_ptr<MsgSip> msg = ev->getMsgSip();
		MsgSip* msgSip = msg.get();
		su_sockaddr_t su[1];
		socklen_t len = sizeof su;
		sockaddr* addr = NULL;
		char ip[NI_MAXHOST], port[NI_MAXSERV];
		int err;

		msg_get_address(msgSip->getMsg(), su, &len);
		addr = &(su[0].su_sa);

		if ((err = getnameinfo(addr, len, ip, sizeof(ip), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV)) == 0) {
			string id = string(ip) + ":" + string(port);
			struct timeval now;
			DosContext& dosContext = mDosContexts[id];
			double now_in_millis, time_elapsed;

			dosContext.recv_msg_count_since_last_check++;
			gettimeofday(&now, NULL);
			now_in_millis = now.tv_sec * 1000 + (now.tv_usec / 1000);
			if (dosContext.last_check_recv_msg_check_time == 0) {
				dosContext.last_check_recv_msg_check_time = now_in_millis;
			}

			time_elapsed = now_in_millis - dosContext.last_check_recv_msg_check_time;
			if (time_elapsed < 0) {
				dosContext.packet_count_rate = 0;
				dosContext.recv_msg_count_since_last_check = 0;
				dosContext.last_check_recv_msg_check_time = now_in_millis;
			} else if (time_elapsed >= mTimePeriod) {
				dosContext.packet_count_rate = dosContext.recv_msg_count_since_last_check / time_elapsed * 1000;
				dosContext.recv_msg_count_since_last_check = 0;
				dosContext.last_check_recv_msg_check_time = now_in_millis;
				LOGD << "Packet count rate (" << dosContext.packet_count_rate << ") for " << ip << ":" << port
				     << " on protocol UDP";
			}

			if (dosContext.packet_count_rate >= mPacketRateLimit) {
				LOGW << "Packet count rate (" << dosContext.packet_count_rate << ") >= limit (" << mPacketRateLimit
				     << "), blocking " << ip << ":" << port << " on protocol UDP for " << mBanTime << " minutes";
				if (!isIpWhiteListed(ip)) {
					mThreadPool->run([&, ip, port] { mBanExecutor->banIP(ip, port, "udp"); });
					registerUnbanTimer(ip, port, "udp");
					ev->terminateProcessing(); // the event is discarded
				} else {
					LOGI << "Address " << ip << " should be banned but was not because it is part of the white list";
				}
				dosContext.packet_count_rate = 0; // Reset it to not add the iptables rule twice by mistake
			}
		} else {
			LOGW << "getnameinfo() failed: " << gai_strerror(err);
		}
	} else {
		unsigned long packet_count_rate = tport_get_packet_count_rate(tport);
		LOGD << "Packet count rate (" << packet_count_rate << ") for current tport on protocol TCP";
		if (packet_count_rate >= (unsigned long)mPacketRateLimit) {
			sockaddr* addr = tport_get_address(tport)->ai_addr;
			socklen_t len = tport_get_address(tport)->ai_addrlen;
			char ip[NI_MAXHOST], port[NI_MAXSERV];
			int err;

			if ((err = getnameinfo(addr, len, ip, sizeof(ip), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV)) ==
			    0) {
				LOGW << "Packet count rate (" << packet_count_rate << ") >= limit (" << mPacketRateLimit
				     << "), blocking " << ip << ":" << port << " on protocol TCP for " << mBanTime << " minutes";
				if (!isIpWhiteListed(ip)) {
					mThreadPool->run([&, ip, port] { mBanExecutor->banIP(ip, port, "tcp"); });
					registerUnbanTimer(ip, port, "tcp");
					ev->terminateProcessing(); // the event is discarded
				} else {
					LOGI << "Address " << ip << " should be banned but was not because it is part of the white list";
				}
				tport_reset_packet_count_rate(tport); // Reset it to not add the iptables rule twice by mistake
			} else {
				LOGW << "getnameinfo() failed: " << gai_strerror(err);
			}
		}
	}
	return std::move(ev);
}

#ifdef ENABLE_UNIT_TESTS
void ModuleDoSProtection::setBanExecutor(const shared_ptr<BanExecutor>& executor) {
	if (mBanExecutor) {
		mBanExecutor->onUnload();
	}
	mBanExecutor = executor;
	mBanExecutor->onLoad(nullptr);
}
#endif