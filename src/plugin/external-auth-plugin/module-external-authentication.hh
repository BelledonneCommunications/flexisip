/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2018  Belledonne Communications SARL, All rights reserved.

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

#pragma once

#include <array>

#include <flexisip/agent.hh>
#include "external-auth-module.hh"
#include <flexisip/module.hh>

class ModuleExternalAuthentication : public Module {
public:
	ModuleExternalAuthentication(Agent *agent);
	~ModuleExternalAuthentication() override = default;

private:
	class _AuthStatus : public ExternalAuthModule::Status {
	public:
		_AuthStatus(const std::shared_ptr<RequestSipEvent> &event): ExternalAuthModule::Status(), mEvent(event) {}

		const std::shared_ptr<RequestSipEvent> &event() const {return mEvent;}

	private:
		std::shared_ptr<RequestSipEvent> mEvent;
	};

	void onDeclare(GenericStruct *mc) override;
	void onLoad(const GenericStruct *root) override;
	void onRequest(std::shared_ptr<RequestSipEvent> &ev) override;
	void onResponse(std::shared_ptr<ResponseSipEvent> &ev) override {}

	ExternalAuthModule *findAuthModule(const std::string name);
	void processAuthModuleResponse(AuthStatus &as);

	std::map<std::string, std::unique_ptr<ExternalAuthModule>> mAuthModules;
	std::list<std::string> mAlgorithms;
	std::map<nth_client_t *, std::shared_ptr<RequestSipEvent>> mPendingEvent;
	auth_challenger_t mRegistrarChallenger;
	auth_challenger_t mProxyChallenger;
};
