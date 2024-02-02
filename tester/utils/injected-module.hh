/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <string>
#include <vector>

#include "flexisip/module.hh"

namespace flexisip::tester {

// A base class for modules to be injected in the Agent module chain for tests purposes
class InjectedModule : public Module {
public:
	// For injection purposes, such modules must be constructed prior to the Agent.
	// The mAgent pointer will be set as part of the Agent's initialisation process
	explicit InjectedModule(const std::vector<std::string>& after) : Module(nullptr), mAfter(after) {
	}

	const std::vector<std::string>& getAfter() const {
		return mAfter;
	}

private:
	std::vector<std::string> mAfter;
};

// Inject custom behaviour into the Agent's requests and responses handling.
// Pass an instance of this class to flexisip::tester::Server's constructor to enable it.
class InjectedHooks : public InjectedModule {
public:
	struct Hooks {
		std::function<void(std::shared_ptr<RequestSipEvent>&)> onRequest = [](auto&) {};
		std::function<void(std::shared_ptr<ResponseSipEvent>&)> onResponse = [](auto&) {};
	};

	explicit InjectedHooks(Hooks&& hooks, const std::vector<std::string>& after = {""})
	    : InjectedModule(after), mHooks(std::move(hooks)) {
	}

private:
	void onRequest(std::shared_ptr<RequestSipEvent>& ev) override {
		mHooks.onRequest(ev);
	}
	void onResponse(std::shared_ptr<ResponseSipEvent>& ev) override {
		mHooks.onResponse(ev);
	}

	Hooks mHooks;
};

} // namespace flexisip::tester
