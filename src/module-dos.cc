/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

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

#include "module.hh"
#include "agent.hh"
#include "log/logmanager.hh"
#include <sofia-sip/tport.h>
#include <sofia-sip/msg_addr.h>
#include <unordered_map>

using namespace std;

typedef struct DosContext {
	uint64_t recv_msg_count_since_last_check;
	double last_check_recv_msg_check_time;
	double packet_count_rate;
} DosContext;

class DoSProtection : public Module, ModuleToolbox {

  private:
	static ModuleInfo<DoSProtection> sInfo;
	int mTimePeriod;
	int mPacketRateLimit;
	int mBanTime;
	bool mAtChecked;
	list<string> mWhiteList;
	unordered_map<string, DosContext> mDosContexts;
	unordered_map<string, DosContext>::iterator mDOSHashtableIterator;

	void onDeclare(GenericStruct *module_config) {
		ConfigItemDescriptor configs[] = {
			{Integer, "time-period", "Number of milliseconds to consider to compute the packet rate", "3000"},
			{Integer, "packet-rate-limit", "Maximum packet rate in packets/seconds,  averaged over [time-period] "
										   "millisecond(s) to consider it as a DoS attack.",
			 "20"},
			{Integer, "ban-time", "Number of minutes to ban the ip/port using iptables (might be less because it justs "
								  "uses the minutes of the clock, not the seconds. So if the unban command is queued "
								  "at 13:11:56 and scheduled and the ban time is 1 minute, it will be executed at "
								  "13:12:00)",
			 "2"},
			config_item_end};
		module_config->get<ConfigBoolean>("enabled")->setDefault("true");
		module_config->addChildrenValues(configs);
	}

	void onLoad(const GenericStruct *mc) {
		mTimePeriod = mc->get<ConfigInt>("time-period")->read();
		mPacketRateLimit = mc->get<ConfigInt>("packet-rate-limit")->read();
		mBanTime = mc->get<ConfigInt>("ban-time")->read();
		mDOSHashtableIterator = mDosContexts.begin();
		
		GenericStruct *cluster = GenericManager::get()->getRoot()->get<GenericStruct>("cluster");
		mWhiteList = cluster->get<ConfigStringList>("nodes")->read();
		for (auto it = mWhiteList.begin(); it != mWhiteList.end(); ++it) {
			const char *white_ip = (*it).c_str();
			LOGI("IP %s is in DOS protection white list", white_ip);
		}
		LOGI("IP 127.0.0.1 automatically added to DOS protection white list");

		tport_t *primaries = tport_primaries(nta_agent_tports(mAgent->getSofiaAgent()));
		if (primaries == NULL)
			LOGF("No sip transport defined.");
		for (tport_t *tport = primaries; tport != NULL; tport = tport_next(tport)) {
			tport_set_params(tport, TPTAG_DOS(mTimePeriod), TAG_END());
		}
		if (getuid() != 0) {
			LOGE("Flexisip not started with root privileges! iptables commands for DoS protection won't work.");
			return;
		}
	}

	void onUnload() {
	}

	virtual bool isValidNextConfig( const ConfigValue &value ) {
		GenericStruct *module_config = dynamic_cast<GenericStruct *>(value.getParent());
		if (!module_config->get<ConfigBoolean>("enabled")->readNext())
			return true;
		else {

#if __APPLE__
			LOGEN("DosProtection only works on linux hosts. Please disable this module.");
			return false;
#else
			// we only want to check 'at' availability once
			if ( !mAtChecked ){
				mAtChecked = true;
				int at_command = system("which at > /dev/null");
				if( WIFEXITED(at_command) && WEXITSTATUS(at_command) == 0 ) {
					// at command was found, we can be sure that iptables rules will be cleaned up after the required time
					return true;
				} else {
					LOGEN("Couldn't find the commant 'at' in your PATH. DosProtection needs it to be used correctly. Please fix this or disable DosProtection.");
					return false;
				}
			}
			return true;
#endif
		}
	}

	void onIdle() {
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
				LOGW("Started to clean dos hashtable %fms ago, let's stop for now a continue later",
					 now_in_millis - started_time_in_millis);
				break;
			}
		}
	}
	
	bool isIpWhiteListed(const char *ip) {
		if (!ip) return true; // If IP is null, is useless to try to add it in iptables...
		
		if (ip && strcmp(ip, "127.0.0.1") == 0) { // Never ban localhost, used for presence
			return true;
		}
		
		for (auto it = mWhiteList.begin(); it != mWhiteList.end(); ++it) { // Never ban ips from cluster
			const char *white_ip = (*it).c_str();
			if (white_ip && strcmp(ip, white_ip) == 0) {
				return true;
			}
		}
		
		return false;
	}

	static void ban_ip_with_iptables(const char *ip, const char *port, const char *protocol, int ban_time) {
		char iptables_cmd[512];
		snprintf(iptables_cmd, sizeof(iptables_cmd), "iptables -w -C INPUT -p %s -s %s -m multiport --sports %s -j DROP", 
				 protocol, ip, port);
		if (system(iptables_cmd) == 0) {
			LOGW("IP %s port %s on protocol %s is already in the iptables banned list, skipping...", ip, port, protocol);
		} else {
			snprintf(iptables_cmd, sizeof(iptables_cmd), "iptables -w -A INPUT -p %s -s %s -m multiport --sports %s -j DROP"
					" && echo \"iptables -w -D INPUT -p %s -s %s -m multiport --sports %s -j DROP\" | at now +%i minutes",
					protocol, ip, port, protocol, ip, port, ban_time);
			if (system(iptables_cmd) != 0) {
				LOGW("iptables command failed: %s", strerror(errno));
			}
		}
	}

	void onRequest(shared_ptr<RequestSipEvent> &ev) throw (FlexisipException) {
		shared_ptr<tport_t> inTport = ev->getIncomingTport();
		tport_t *tport = inTport.get();

		if (tport == NULL) {
			LOGE("Tport is null, can't check the packet count rate");
			return;
		}

		if (tport_is_udp(tport)) { // Sofia doesn't create a secondary tport for udp, so it will ban the primary and we
								   // don't want that
			shared_ptr<MsgSip> msg = ev->getMsgSip();
			MsgSip *msgSip = msg.get();
			su_sockaddr_t su[1];
			socklen_t len = sizeof su;
			sockaddr *addr = NULL;
			char ip[NI_MAXHOST], port[NI_MAXSERV];
			int err;

			msg_get_address(msgSip->getMsg(), su, &len);
			addr = &(su[0].su_sa);

			if ((err = getnameinfo(addr, len, ip, sizeof(ip), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV)) ==
				0) {
				string id = string(ip) + ":" + string(port);
				struct timeval now;
				DosContext &dosContext = mDosContexts[id];
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
				}

				if (dosContext.packet_count_rate >= mPacketRateLimit) {
					LOGW("Packet count rate (%f) >= limit (%i), blocking ip/port %s/%s on protocol udp for %i minutes",
						 dosContext.packet_count_rate, mPacketRateLimit, ip, port, mBanTime);
					if (!isIpWhiteListed(ip)) {
						ban_ip_with_iptables(ip, port, "udp", mBanTime);
						ev->terminateProcessing(); // the event is discarded
					} else {
						LOGW("IP %s should be banned but wasn't because in white list", ip);
					}
					dosContext.packet_count_rate = 0; // Reset it to not add the iptables rule twice by mistake
				}
			} else {
				LOGW("getnameinfo() failed: %s", gai_strerror(err));
			}
		} else {
			float packet_count_rate = tport_get_packet_count_rate(tport);
			if (packet_count_rate >= mPacketRateLimit) {
				sockaddr *addr = tport_get_address(tport)->ai_addr;
				socklen_t len = tport_get_address(tport)->ai_addrlen;
				char ip[NI_MAXHOST], port[NI_MAXSERV];
				int err;

				if ((err = getnameinfo(addr, len, ip, sizeof(ip), port, sizeof(port),
									   NI_NUMERICHOST | NI_NUMERICSERV)) == 0) {
					LOGW("Packet count rate (%f) >= limit (%i), blocking ip/port %s/%s on protocol tcp for %i minutes",
						 packet_count_rate, mPacketRateLimit, ip, port, mBanTime);
					if (!isIpWhiteListed(ip)) {
						ban_ip_with_iptables(ip, port, "tcp", mBanTime);
						ev->terminateProcessing(); // the event is discarded
					} else {
						LOGW("IP %s should be banned but wasn't because in white list", ip);
					}
					tport_reset_packet_count_rate(tport); // Reset it to not add the iptables rule twice by mistake
				} else {
					LOGW("getnameinfo() failed: %s", gai_strerror(err));
				}
			}
		}
	}

	void onResponse(std::shared_ptr<ResponseSipEvent> &ev) throw (FlexisipException){

	};

  public:
	DoSProtection(Agent *ag) : Module(ag) {
		mAtChecked = false;
	}

	~DoSProtection() {
	}
};

ModuleInfo<DoSProtection>
	DoSProtection::sInfo("DoSProtection",
						 "This module bans user when they are sending too much packets on a given timelapse"
						 "To see the list of currently banned ips/ports, use iptables -L"
						 "You can also check the queue of unban commands using atq",
						 ModuleInfoBase::ModuleOid::DoSProtection);
