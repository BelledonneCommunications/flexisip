/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2014  Belledonne Communications SARL.

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

using namespace ::std;

typedef struct DosContext {
    uint64_t recv_msg_count_since_last_check;
	double last_check_recv_msg_check_time;
	double packet_count_rate;
} DosContext;

class ModuleDoS: public Module, ModuleToolbox {

private:
	static ModuleInfo<ModuleDoS> sInfo;
	int mTimePeriod;
	int mPacketRateLimit;
	int mBanTime;
	unordered_map<string, DosContext> mDosContexts;

	void onDeclare(GenericStruct *module_config) {
		ConfigItemDescriptor configs[] = {
			{ Integer , "time-period", "Number of milliseconds to calculate the packet rate", "3000"},
			{ Integer , "packet-rate-limit", "Maximum packet rate received in [time-period] millisecond(s) to consider to consider it a DoS attack.", "10"},
			{ Integer , "ban-time", "Number of minutes to ban the ip/port using iptables (might be less because it justs uses the minutes of the clock, not the seconds. So if the unban command is queued at 13:11:56 and scheduled and the ban time is 1 minute, it will be executed at 13:12:00)", "2"},
			config_item_end
		};
		module_config->get<ConfigBoolean>("enabled")->setDefault("true");
		module_config->addChildrenValues(configs);
	}

	void onLoad(const GenericStruct *mc) {
		mTimePeriod = mc->get<ConfigInt>("time-period")->read();
		mPacketRateLimit = mc->get<ConfigInt>("packet-rate-limit")->read();
		mBanTime = mc->get<ConfigInt>("ban-time")->read();
		
		tport_t *primaries=tport_primaries(nta_agent_tports(mAgent->getSofiaAgent()));
		if (primaries == NULL) LOGF("No sip transport defined.");
		for(tport_t *tport = primaries; tport != NULL; tport = tport_next(tport)) {
			tport_set_params(tport, TPTAG_DOS(mTimePeriod), TAG_END());
		}
	}

	void onUnload() {
		
	}
	
	void onRequest(shared_ptr<RequestSipEvent> &ev) {
		shared_ptr<tport_t> inTport = ev->getIncomingTport();
		tport_t *tport = inTport.get();
		
		if (tport == NULL) {
			LOGE("Tport is null, can't check the packet count rate");
			return;
		}
		
		if (tport_is_udp(tport)) { // Sofia doesn't create a secondary tport for udp, so it will ban the primary and we don't want that
			shared_ptr<MsgSip> msg = ev->getMsgSip();
			MsgSip *msgSip = msg.get();
			su_sockaddr_t su[1];
			socklen_t len = sizeof su;
			sockaddr *addr = NULL;
			char ip[NI_MAXHOST], port[NI_MAXSERV];
			char iptables_cmd[512];
			msg_get_address(msgSip->getMsg(), su, &len);
			addr = &(su[0].su_sa);
			
			if (addr != NULL && getnameinfo(addr, len, ip, sizeof(ip), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
				string id = string(ip) + ":" + string(port);
				struct timeval now;
				DosContext dosContext = mDosContexts[id];
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
					if (getuid() != 0) {
						LOGE("Flexisip not started with root privileges! Can't add iptables rule");
						return;
					}
					LOGW("Packet count rate (%f) >= limit (%i), blocking ip/port %s/%s on protocol udp for %i minutes", dosContext.packet_count_rate, mPacketRateLimit, ip, port, mBanTime);
					snprintf(iptables_cmd, sizeof(iptables_cmd), "iptables -A INPUT -p udp -s %s -m multiport --sports %s -j DROP && echo \"iptables -D INPUT -p udp -s %s -m multiport --sports %s -j DROP\" | at now +%i minutes", 
						ip, port, ip, port, mBanTime);
					if(system(iptables_cmd) != 0) {
						LOGW("iptables command failed");
					}
					dosContext.packet_count_rate = 0; // Reset it to not add the iptables rule twice by mistake
				}
				
				mDosContexts[id] = dosContext;
			}
		} else {
			float packet_count_rate = tport_get_packet_count_rate(tport);
			if (packet_count_rate >= mPacketRateLimit) {
				char iptables_cmd[512];
				sockaddr *addr = tport_get_address(tport)->ai_addr;
				socklen_t len = tport_get_address(tport)->ai_addrlen;
				char ip[NI_MAXHOST], port[NI_MAXSERV];
				if (getnameinfo(addr, len, ip, sizeof(ip), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
					if (getuid() != 0) {
						LOGE("Flexisip not started with root privileges! Can't add iptables rule");
						return;
					}
					LOGW("Packet count rate (%f) >= limit (%i), blocking ip/port %s/%s on protocol tcp for %i minutes", packet_count_rate, mPacketRateLimit, ip, port, mBanTime);
					snprintf(iptables_cmd, sizeof(iptables_cmd), "iptables -A INPUT -p tcp -s %s -m multiport --sports %s -j DROP && echo \"iptables -D INPUT -p tcp -s %s -m multiport --sports %s -j DROP\" | at now +%i minutes", 
						ip, port, ip, port, mBanTime);
					if(system(iptables_cmd) != 0) {
						LOGW("iptables command failed");
					}
				}
				
				tport_reset_packet_count_rate(tport); // Reset it to not add the iptables rule twice by mistake
			}
		}
	}
	
	void onResponse(std::shared_ptr<ResponseSipEvent> &ev) {
		
	};

public:
		ModuleDoS(Agent *ag) : Module(ag) {
			
		}

		~ModuleDoS() {
			
		}
};

ModuleInfo<ModuleDoS> ModuleDoS::sInfo("DoS",
		"This module bans user when they are sending too much packets on a given timelapse"
		"To see the list of currently banned ips/ports, use iptables -L"
		"You can also check the queue of unban commands using atq",
		ModuleInfoBase::ModuleOid::DoS);