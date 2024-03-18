/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "redis-host.hh"

#include "flexisip/logmanager.hh"

#include "utils/string-utils.hh"

namespace flexisip::redis::async {

using namespace std;

RedisHost RedisHost::parseSlave(const string& slaveLine, int id) {
	istringstream input(slaveLine);
	vector<string> context;
	// a slave line has this format for redis < 2.8: "<host>,<port>,<state>"
	// for redis > 2.8 it is this format: "ip=<ip>,port=<port>,state=<state>,...(key)=(value)"

	// split the string with ',' into an array
	for (string token; getline(input, token, ',');)
		context.push_back(token);

	if (context.size() > 0 && (context.at(0).find('=') != string::npos)) {
		// we have found an "=" in one of the values: the format is post-Redis 2.8.
		// We have to parse is accordingly.
		auto m = StringUtils::parseKeyValue(slaveLine, ',', '=');

		if (m.find("ip") != m.end() && m.find("port") != m.end() && m.find("state") != m.end()) {
			return RedisHost(id, m.at("ip"), atoi(m.at("port").c_str()), m.at("state"));
		} else {
			SLOGW << "Missing fields in the slaveline " << slaveLine;
		}
	} else if (context.size() >= 3) {
		// Old-style slave format, use the context from the array directly
		return RedisHost(id, context[0],                           // host
		                 (unsigned short)atoi(context[1].c_str()), // port
		                 context[2]);                              // state
	} else {
		SLOGW << "Invalid host line: " << slaveLine;
	}
	return RedisHost(); // invalid host
}
} // namespace flexisip::redis::async
