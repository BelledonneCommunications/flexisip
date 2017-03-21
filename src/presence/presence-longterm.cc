#include "presence-longterm.hh"
#include "presentity-presenceinformation.hh"

#include <belle-sip/belle-sip.h>

using namespace flexisip;

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

	virtual void onResult(AuthDbResult result, const std::string &passwd) {
		belle_sip_source_cpp_func_t *func = new belle_sip_source_cpp_func_t([this, result, passwd](unsigned int events) {
			this->processResponse(result, passwd);
			return BELLE_SIP_STOP;
		});
		belle_sip_source_t *timer = belle_sip_main_loop_create_cpp_timeout(  mMainLoop
			, func
			, 0
			, "OnAuthListener to mainthread");
		belle_sip_object_unref(timer);
	}
	
	void onResults(list<std::string> &phones, set<std::string> &users) {
		for(std::string phone : phones) {
			if(users.size() == 0) {
				this->onResult(PASSWORD_NOT_FOUND, phone);
			} else if (users.find(phone) != users.end()){
				this->onResult(PASSWORD_FOUND, phone);
			} else {
				this->onResult(PASSWORD_NOT_FOUND, phone);
			}
		}
	}

private:

	void processResponse(AuthDbResult result, const std::string &user) {
		std::shared_ptr<PresentityPresenceInformation> info;
		bool must_delete = FALSE;
		if(mInfo == nullptr) {
			std::map<std::string,std::shared_ptr<PresentityPresenceInformation>>::iterator it = mDInfo.find(user);
			info = it->second;
		} else {
			info = mInfo;
			must_delete = TRUE;
		}
		const char* cuser = belle_sip_uri_get_user(info->getEntity());
		if (result == AuthDbResult::PASSWORD_FOUND) {
			// result is a phone alias if (and only if) user is not the same as the entity user
			bool isPhone = (strcmp(user.c_str(), cuser) != 0);
			if (isPhone) {
				// change contact accordingly
				belle_sip_uri_t *uri = BELLE_SIP_URI(belle_sip_object_clone(BELLE_SIP_OBJECT(info->getEntity())));
				belle_sip_parameters_t* params=BELLE_SIP_PARAMETERS(uri);
				belle_sip_parameters_remove_parameter(params, "user");
				belle_sip_uri_set_user(uri, user.c_str());
				char *contact_as_string = belle_sip_uri_to_string(uri);
				belle_sip_object_unref(uri);
				SLOGD << __FILE__ << ": " << "Found user " << user << " for phone "
					<< belle_sip_uri_get_user(info->getEntity()) << ", adding contact " << contact_as_string << " presence information";
				info->setDefaultElement(contact_as_string);
				belle_sip_free(contact_as_string);
			} else {
				SLOGD << __FILE__ << ": " << "Found user " << user << ", adding presence information";
				info->setDefaultElement();
			}
		} else {
			SLOGD << __FILE__ << ": " << "Could not find user " << cuser << ".";
		}
		if(must_delete) {
			delete this;
		}
	}
	
private:
	belle_sip_main_loop_t *mMainLoop;
	const std::shared_ptr<PresentityPresenceInformation> mInfo;
	std::map<std::string,std::shared_ptr<PresentityPresenceInformation>> mDInfo;
};

void PresenceLongterm::onNewPresenceInfo(const std::shared_ptr<PresentityPresenceInformation>& info) const {
	//no longuer used because long term presence is check at each subscription in case not known yet
	
	//const belle_sip_uri_t* uri = info->getEntity();
	//SLOGD << __FILE__ << ": " << "New presence info for " << belle_sip_uri_get_user(uri) << ", checking if this user is already registered";
	//AuthDbBackend::get()->getUserWithPhone(belle_sip_uri_get_user(info->getEntity()), belle_sip_uri_get_host(info->getEntity()), new PresenceAuthListener(mMainLoop, info));
}
void PresenceLongterm::onListenerEvent(const std::shared_ptr<PresentityPresenceInformation>& info) const {
	if (!info->hasDefaultElement()) {
		//no presence information know yet, so ask again to the db.
		const belle_sip_uri_t* uri = info->getEntity();
		SLOGD << "No presence info element known yet for " << belle_sip_uri_get_user(uri) << ", checking if this user is already registered";
		AuthDbBackend::get()->getUserWithPhone(belle_sip_uri_get_user(info->getEntity())
											   , belle_sip_uri_get_host(info->getEntity())
											   , new PresenceAuthListener(mMainLoop, info));
	}
}
void PresenceLongterm::onListenerEvents(list<std::shared_ptr<PresentityPresenceInformation>>& infos) const {
	list<tuple<std::string,std::string,AuthDbListener*>> creds;
	std::map<std::string,std::shared_ptr<PresentityPresenceInformation>> dInfo;
	for (shared_ptr<PresentityPresenceInformation> &info : infos) {
		if (!info->hasDefaultElement()) {
			creds.push_back(make_tuple(belle_sip_uri_get_user(info->getEntity()), belle_sip_uri_get_host(info->getEntity()), new PresenceAuthListener(mMainLoop, info)));
		}
		dInfo.insert(std::pair<std::string,std::shared_ptr<PresentityPresenceInformation>>(belle_sip_uri_get_user(info->getEntity()), info));
	}
	
	AuthDbBackend::get()->getUsersWithPhone(creds
										   , new PresenceAuthListener(mMainLoop, dInfo));
}
