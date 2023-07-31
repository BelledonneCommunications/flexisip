/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string_view>

#include <bctoolbox/ownership.hh>
#include <utility>

#include "agent-test.hh"
#include "utils/contact-inserter.hh"
#include "utils/redis-server.hh"

namespace flexisip {
namespace tester {

namespace DbImplementation {

class Internal {
public:
	void amendConfiguration(GenericManager& cfg) {
		auto* registrarConf = cfg.getRoot()->get<GenericStruct>("module::Registrar");
		registrarConf->get<ConfigValue>("db-implementation")->set("internal");
	}

	std::map<std::string, std::string> configAsMap() {
		return {
		    {"module::Registrar/db-implementation", "internal"},
		};
	}
};

class Redis {
public:
	void amendConfiguration(GenericManager& cfg) {
		auto* registrarConf = cfg.getRoot()->get<GenericStruct>("module::Registrar");
		registrarConf->get<ConfigValue>("db-implementation")->set("redis");
		registrarConf->get<ConfigValue>("redis-server-domain")->set("localhost");
		registrarConf->get<ConfigValue>("redis-server-port")->set(std::to_string(mRedisServer.port()));
	}

	std::map<std::string, std::string> configAsMap() {
		return {{"module::Registrar/db-implementation", "redis"},
		        {"module::Registrar/redis-server-domain", "localhost"},
		        {"module::Registrar/redis-server-port", std::to_string(mRedisServer.port())}};
	}

	auto port() {
		return mRedisServer.port();
	}

private:
	RedisServer mRedisServer{};
};

} // namespace DbImplementation

template <typename TDatabase>
class RegistrarDbTest : public AgentTest {
public:
	RegistrarDbTest(bool startAgent = false) noexcept : AgentTest(startAgent) {
	}
	~RegistrarDbTest() {
		RegistrarDb::resetDB();
	}

	void onAgentConfiguration(GenericManager& cfg) override {
		AgentTest::onAgentConfiguration(cfg);
		dbImpl.amendConfiguration(cfg);
	}

	void onAgentConfigured() override {
		mInserter.emplace(*RegistrarDb::get());
	}

	std::optional<ContactInserter> mInserter{std::nullopt};

protected:
	TDatabase dbImpl;
};

} // namespace tester
} // namespace flexisip
