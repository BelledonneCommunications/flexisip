/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "flexisip/module.hh"
#include "random.hh"

namespace flexisip::tester {

/**
 * Inject custom behaviour into the Agent's requests and responses handling.
 */
struct InjectedHooks {
	using OnRequestCallback = std::function<std::unique_ptr<RequestSipEvent>(std::unique_ptr<RequestSipEvent>&&)>;
	using OnResponseCallback = std::function<std::unique_ptr<ResponseSipEvent>(std::unique_ptr<ResponseSipEvent>&&)>;

	std::string injectAfterModule{};
	OnRequestCallback onRequest = [](auto&& ev) { return std::move(ev); };
	OnResponseCallback onResponse = [](auto&& ev) { return std::move(ev); };
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
	          Plugin,
	          [](GenericStruct&) {},
	          ModuleClass::Production,
	          ""),
	      mModuleHooks(moduleHooks) {}

private:
	/**
	 * A base class for modules to be injected in the Agent module chain for tests purposes
	 */
	class InjectedModule : public Module {
	public:
		InjectedModule(Agent* ag, const ModuleInfoBase* moduleInfo, const InjectedHooks& hooks)
		    : Module(ag, moduleInfo), mHooks(hooks) {}

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