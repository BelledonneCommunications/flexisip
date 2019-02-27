#include <belle-sip/belle-sip.h>

#include <flexisip/registrardb.hh>

#include "presence-longterm.hh"
#include "presentity-presenceinformation.hh"

using namespace flexisip;
using namespace std;

class PresenceAuthListener : public AuthDbListener {
public:
	PresenceAuthListener(belle_sip_main_loop_t *mainLoop, const std::shared_ptr<PresentityPresenceInformation> &info)
	: mMainLoop(mainLoop), mInfo(info) {
		AuthDbBackend::get(); /*this will initialize the database backend, which is good to know that it works at startup*/
	}
	PresenceAuthListener(belle_sip_main_loop_t *mainLoop, std::map<std::string,std::shared_ptr<PresentityPresenceInformation>> &dInfo)
	: mMainLoop(mainLoop), mDInfo(dInfo) {
		AuthDbBackend::get(); /*this will initialize the database backend, which is good to know that it works at startup*/
	}

	void onResult(AuthDbResult result, const std::string &passwd) override {
		belle_sip_source_cpp_func_t *func = new belle_sip_source_cpp_func_t([this, result, passwd](unsigned int events) {
			processResponse(result, passwd);
			return BELLE_SIP_STOP;
		});
		belle_sip_source_t *timer = belle_sip_main_loop_create_cpp_timeout(  mMainLoop
			, func
			, 0
			, "OnAuthListener to mainthread");
		belle_sip_object_unref(timer);
	}

	void onResult(AuthDbResult result, const vector<passwd_algo_t> &passwd) override {
		belle_sip_source_cpp_func_t *func = new belle_sip_source_cpp_func_t([this, result, passwd](unsigned int events) {
			processResponse(result, passwd.front().pass);
			return BELLE_SIP_STOP;
		});
		belle_sip_source_t *timer = belle_sip_main_loop_create_cpp_timeout(  mMainLoop
																		, func
																		, 0
																		, "OnAuthListener to mainthread");
		belle_sip_object_unref(timer);
	}

	void finishVerifyAlgos(const vector<passwd_algo_t> &pass) override {}

private:
	void processResponse(AuthDbResult result, const std::string &user) {
		shared_ptr<PresentityPresenceInformation> info = mInfo ? mInfo : mDInfo.find(user)->second;

		const char *cuser = belle_sip_uri_get_user(info->getEntity());
		if (result == AuthDbResult::PASSWORD_FOUND) {
			// result is a phone alias if (and only if) user is not the same as the entity user
			bool isPhone = (strcmp(user.c_str(), cuser) != 0);
			belle_sip_uri_t *uri = BELLE_SIP_URI(belle_sip_object_clone(BELLE_SIP_OBJECT(info->getEntity())));
			char *contact_as_string = belle_sip_uri_to_string(uri);
			if (isPhone) {
				// change contact accordingly
				belle_sip_free(contact_as_string);
				belle_sip_parameters_t *params = BELLE_SIP_PARAMETERS(uri);
				belle_sip_parameters_remove_parameter(params, "user");
				belle_sip_uri_set_user(uri, user.c_str());
				contact_as_string = belle_sip_uri_to_string(uri);
				SLOGD << __FILE__ << ": " << "Found user " << user << " for phone "
					<< belle_sip_uri_get_user(info->getEntity()) << ", adding contact " << contact_as_string << " presence information";
				info->setDefaultElement(contact_as_string);
			} else {
				SLOGD << __FILE__ << ": " << "Found user " << user << ", adding presence information";
				info->setDefaultElement();
			}
			belle_sip_object_unref(uri);

			class InternalListListener : public ContactUpdateListener {
			public:
				InternalListListener(shared_ptr<PresentityPresenceInformation> info) : mInfo(info) {}

				void onRecordFound(const std::shared_ptr<Record> &record) {
					if (!record) return;

					for (const auto extendedContact : record->getExtendedContacts()) {
						const string specs = extendedContact->getOrgLinphoneSpecs();
						if (!specs.empty())
							mInfo->addCapability(specs);
					}
				}
				void onError() {}
				void onInvalid() {}
				void onContactUpdated(const std::shared_ptr<ExtendedContact> &) {}

				su_home_t *getHome() { return mHome.home(); }

			private:
				SofiaAutoHome mHome;
				shared_ptr<PresentityPresenceInformation> mInfo;
			};

			// Fetch Redis info.
			shared_ptr<InternalListListener> listener = make_shared<InternalListListener>(info);
			url_t *url = url_make(listener->getHome(), contact_as_string);
			RegistrarDb::get()->fetch(url, listener);
			belle_sip_free(contact_as_string);
		} else {
			SLOGD << __FILE__ << ": " << "Could not find user " << cuser << ".";
		}
		delete this;
	}

	belle_sip_main_loop_t *mMainLoop;
	const shared_ptr<PresentityPresenceInformation> mInfo;
	map<string, shared_ptr<PresentityPresenceInformation>> mDInfo;
};

void PresenceLongterm::onListenerEvent(const shared_ptr<PresentityPresenceInformation>& info) const {
	if (!info->hasDefaultElement()) {
		//no presence information know yet, so ask again to the db.
		const belle_sip_uri_t* uri = info->getEntity();
		SLOGD << "No presence info element known yet for " << belle_sip_uri_get_user(uri) << ", checking if this user is already registered";
		AuthDbBackend::get().getUserWithPhone(belle_sip_uri_get_user(info->getEntity())
											, belle_sip_uri_get_host(info->getEntity())
											, new PresenceAuthListener(mMainLoop, info));
	}
}
void PresenceLongterm::onListenerEvents(list<shared_ptr<PresentityPresenceInformation>>& infos) const {
	list<tuple<string, string,AuthDbListener*>> creds;
	map<string, shared_ptr<PresentityPresenceInformation>> dInfo;
	for (const shared_ptr<PresentityPresenceInformation> &info : infos) {
		if (!info->hasDefaultElement()) {
			creds.push_back(make_tuple(belle_sip_uri_get_user(info->getEntity()), belle_sip_uri_get_host(info->getEntity()), new PresenceAuthListener(mMainLoop, info)));
		}
		dInfo.insert(pair<string, shared_ptr<PresentityPresenceInformation>>(belle_sip_uri_get_user(info->getEntity()), info));
	}
	AuthDbBackend::get().getUsersWithPhone(creds);
}
