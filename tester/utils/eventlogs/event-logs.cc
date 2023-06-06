/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <linphone++/linphone.hh>

#include "event-logs.hh"

using namespace std;

namespace flexisip {
namespace tester {
namespace eventlogs {

shared_ptr<Server> makeAndStartProxy(std::map<std::string, std::string> customConfigs) {
	customConfigs.merge(map<string, string>{
	    // Requesting bind on port 0 to let the kernel find any available port
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "sip.example.org"},
	    {"module::MediaRelay/enabled", "true"},
	    {"module::MediaRelay/prevent-loops", "false"}, // Allow loopback to localnetwork
	});
	const auto proxy = make_shared<Server>(customConfigs);
	proxy->start();
	return proxy;
}

} // namespace eventlogs
} // namespace tester
} // namespace flexisip
