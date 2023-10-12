/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include "presence-auth-db-listener.hh"

#include <belle-sip/belle-sip.h>

#include "flexisip/registrar/registar-listeners.hh"

#include "registrar/extended-contact.hh"
#include "registrar/record.hh"
#include "registrar/registrar-db.hh"

using namespace flexisip;
using namespace std;

PresenceAuthDbListener::PresenceAuthDbListener(belle_sip_main_loop_t* mainLoop,
                                               const std::shared_ptr<PresentityPresenceInformation>& info,
                                               const std::shared_ptr<RegistrarDb>& registrarDb)
    : mMainLoop(mainLoop), mRegistrarDb(registrarDb), mInfo(info) {
}

PresenceAuthDbListener::PresenceAuthDbListener(
    belle_sip_main_loop_t* mainLoop,
    const unordered_map<std::string, std::shared_ptr<PresentityPresenceInformation>>& dInfo,
    const std::shared_ptr<RegistrarDb>& registrarDb)
    : mMainLoop(mainLoop), mRegistrarDb(registrarDb), mDInfo(dInfo) {
}

void PresenceAuthDbListener::onResult(AuthDbResult result, const std::string& passwd) {
	auto func = [this, result, passwd]() { processResponse(result, passwd); };
	belle_sip_main_loop_cpp_do_later(mMainLoop, func, "OnAuthListener to mainthread");
}

void PresenceAuthDbListener::onResult(AuthDbResult result, const std::vector<passwd_algo_t>& passwd) {
	auto func = [this, result, passwd]() { processResponse(result, passwd.front().pass); };
	belle_sip_main_loop_cpp_do_later(mMainLoop, func, "OnAuthListener to mainthread");
}

void PresenceAuthDbListener::processResponse(AuthDbResult result, const string& user) {
	shared_ptr<PresentityPresenceInformation> info = mInfo ? mInfo : mDInfo.find(user)->second;

	const char* cuser = belle_sip_uri_get_user(info->getEntity());
	if (result == AuthDbResult::PASSWORD_FOUND) {
		auto isPhone = false;
		if (const auto userParam = belle_sip_uri_get_user_param(info->getEntity())) {
			isPhone = strcmp(userParam, "phone") == 0;
		}
		// result is a phone alias if (and only if) user is not the same as the entity user
		auto isAlias = strcmp(user.c_str(), cuser) != 0;
		auto* uri = BELLE_SIP_URI(belle_sip_object_clone(BELLE_SIP_OBJECT(info->getEntity())));
		char* contactString = belle_sip_uri_to_string(uri);
		if (isAlias || isPhone) {
			// change contact accordingly
			belle_sip_free(contactString);
			auto* params = BELLE_SIP_PARAMETERS(uri);
			belle_sip_parameters_remove_parameter(params, "user");
			belle_sip_uri_set_user(uri, user.c_str());
			contactString = belle_sip_uri_to_string(uri);
			SLOGD << __FILE__ << ": "
			      << "Found user " << user << " for phone " << belle_sip_uri_get_user(info->getEntity())
			      << ", adding contact " << contactString << " presence information";
			info->setDefaultElement(uri);
		} else {
			SLOGD << __FILE__ << ": "
			      << "Found user " << user << ", adding presence information";
			info->setDefaultElement();
		}
		belle_sip_object_unref(uri);

		class InternalListListener : public ContactUpdateListener {
		public:
			explicit InternalListListener(const shared_ptr<PresentityPresenceInformation>& info) : mInfo(info) {
			}

			void onRecordFound(const std::shared_ptr<Record>& record) override {
				if (!record) return;

				for (const auto& extendedContact : record->getExtendedContacts()) {
					const string specs = extendedContact->getOrgLinphoneSpecs();
					if (!specs.empty()) mInfo->addCapability(specs);
				}
			}
			void onError(const SipStatus&) override{/* Do nothing */};
			void onInvalid(const SipStatus&) override{/* Do nothing */};
			void onContactUpdated(const std::shared_ptr<ExtendedContact>&) override{/* Do nothing */};

			su_home_t* getHome() {
				return mHome.home();
			}

		private:
			sofiasip::Home mHome;
			shared_ptr<PresentityPresenceInformation> mInfo;
		};

		// Fetch Redis info.
		auto listener = make_shared<InternalListListener>(info);
		mRegistrarDb->fetch(SipUri{contactString}, listener);
		belle_sip_free(contactString);
	} else {
		SLOGD << __FILE__ << ": "
		      << "Could not find user " << cuser << ".";
	}
	delete this;
}
