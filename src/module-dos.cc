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
	int mPacketRateLimit;

	void onDeclare(GenericStruct *module_config) {
		ConfigItemDescriptor configs[] = {
			{ Integer , "packet_rate_limit", "Maximum packet rate received in 1 second to consider to consider it a DoS attack.","10"},
			config_item_end
		};
		module_config->get<ConfigBoolean>("enabled")->setDefault("false");
		module_config->addChildrenValues(configs);
	}

	void onLoad(const GenericStruct *mc) {
		mPacketRateLimit = mc->get<ConfigInt>("packet_rate_limit")->read();
	}

	void onUnload() {
		
	}
	
	void onRequest(shared_ptr<RequestSipEvent> &ev) {
		shared_ptr<tport_t> inTport = ev->getIncomingTport();
		tport_t *tport = inTport.get();
		float packet_count_rate = tport_get_packet_count_rate(tport);
		LOGD("Packet count rate for current tport is: %f", packet_count_rate);
		if (packet_count_rate >= mPacketRateLimit) {
			LOGW("Packet count rate is > to the limit %i", mPacketRateLimit);
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

ModuleInfo<ModuleDoS> ModuleDoS::sInfo("DoS protection",
		"This module bans user when they are sending too much packets on a given timelapse",
		ModuleInfoBase::ModuleOid::DoS);