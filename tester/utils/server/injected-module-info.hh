/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "flexisip/module.hh"
#include "utils/rand.hh"

namespace flexisip::tester {

/**
 * Inject custom behaviour into the Agent's requests and responses handling.
 */
struct InjectedHooks {
	std::string injectAfterModule{};
	std::function<std::unique_ptr<RequestSipEvent>(std::unique_ptr<RequestSipEvent>&&)> onRequest = [](auto&& ev) {
		return std::move(ev);
	};
	std::function<std::unique_ptr<ResponseSipEvent>(std::unique_ptr<ResponseSipEvent>&&)> onResponse = [](auto&& ev) {
		return std::move(ev);
	};
};

/**
 * A helper to register a custom module instance to the Agent's module chain.
 * Pass an instance of this class to flexisip::tester::Server's constructor to enable it.
 */
class InjectedModuleInfo : public ModuleInfoBase {
public:
	InjectedModuleInfo(const InjectedHooks& moduleHooks)
	    : ModuleInfoBase(
	          "InjectedTestModule-" + mRsg.generate(10),
	          "A module injected as high up in the module chain as possible to mangle requests and "
	          "responses before they reach other modules",
	          {moduleHooks.injectAfterModule},
	          static_cast<ModuleInfoBase::ModuleOid>(0xdead),
	          [](GenericStruct&) {},
	          ModuleClass::Production,
	          ""),
	      mModuleHooks(moduleHooks) {
	}

private:
	/**
	 * A base class for modules to be injected in the Agent module chain for tests purposes
	 */
	class InjectedModule : public Module {
	public:
		InjectedModule(Agent* ag, const ModuleInfoBase* moduleInfo, const InjectedHooks& hooks)
		    : Module(ag, moduleInfo), mHooks(hooks) {
		}

	private:
		std::unique_ptr<RequestSipEvent> onRequest(std::unique_ptr<RequestSipEvent>&& ev) override {
			return mHooks.onRequest(std::move(ev));
		}
		std::unique_ptr<ResponseSipEvent> onResponse(std::unique_ptr<ResponseSipEvent>&& ev) override {
			return mHooks.onResponse(std::move(ev));
		}
		const InjectedHooks& mHooks;
	};

	// Cannot use underscore character here, so we define a custom alphabet.
	static constexpr auto kAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

	static Random mRandom;
	static Random::StringGenerator mRsg;

	std::shared_ptr<Module> create(Agent* agent) override {
		auto module = std::make_shared<InjectedModule>(agent, this, mModuleHooks);
		return module;
	}

	const InjectedHooks& mModuleHooks;
};

} // namespace flexisip::tester