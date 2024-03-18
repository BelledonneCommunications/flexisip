/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <string>

namespace flexisip::redis::async {

/**
 * @brief The RedisHost struct, which is used to store redis slave description.
 */
struct RedisHost {
	RedisHost(int id, const std::string& address, unsigned short port, const std::string& state)
	    : id(id), address(address), port(port), state(state) {
	}

	RedisHost() : id(-1), port(0){/*invalid host*/};

	inline bool operator==(const RedisHost& r) const {
		return id == r.id && address == r.address && port == r.port && state == r.state;
	}

	/**
	 * @brief parseSlave this class method will parse a line from Redis where a slave information is expected.
	 *
	 * If the parsing goes well, the returned RedisHost will have the id field set to the one passed as argument,
	 * otherwise -1.
	 * @param slaveLine the Redis answer line where a slave is defined. Format is "host,port,state"
	 * @param id an ID to give to this slave, usually its number.
	 * @return A RedisHost with a valid ID or -1 if the parsing failed.
	 */
	static RedisHost parseSlave(const std::string& slaveLine, int id);
	int id;
	std::string address;
	unsigned short port;
	std::string state;
};

} // namespace flexisip::redis::async
