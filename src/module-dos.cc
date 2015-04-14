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

using namespace ::std;

class ModuleDoS: public Module, ModuleToolbox {

private:
	static ModuleInfo<ModuleDoS> sInfo;
	int mTimePeriod;
	int mPacketRateLimit;
	int mBanTime;

	void onDeclare(GenericStruct *module_config) {
		ConfigItemDescriptor configs[] = {
			{ Integer , "time-period", "Number of milliseconds to calculate the packet rate", "1000"},
			{ Integer , "packet-rate-limit", "Maximum packet rate received in [time-period] millisecond(s) to consider to consider it a DoS attack.", "10"},
			{ Integer , "ban-time", "Number of minutes to ban the ip/port using iptables", "1"},
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
		float packet_count_rate = tport_get_packet_count_rate(tport);
		LOGD("Packet count rate (%f)", packet_count_rate);
		
		if (packet_count_rate >= mPacketRateLimit && !tport_is_udp(tport)) { // Sofia doesn't create a secondary tport for udp, so it will ban the primary and we don't want that
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
				system(iptables_cmd);
			}
			
			tport_reset_packet_count_rate(tport);
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
		"This module bans user when they are sending too much packets on a given timelapse",
		ModuleInfoBase::ModuleOid::DoS);