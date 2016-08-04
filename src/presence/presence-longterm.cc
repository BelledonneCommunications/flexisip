#include "presence-longterm.hh"
#include "presentity-presenceinformation.hh"

#include <belle-sip/belle-sip.h>

using namespace flexisip;

class OnAuthListener : public AuthDbListener {
public:
	OnAuthListener(belle_sip_main_loop_t *mainLoop, const std::shared_ptr<PresentityPresenceInformation> info)
	: mMainLoop(mainLoop), mInfo(info) {}

	virtual void onResult(AuthDbResult result, std::string passwd) {
		belle_sip_source_cpp_func_t *func = new belle_sip_source_cpp_func_t([this, result, passwd](unsigned int events) {
			this->processResponse(result, passwd);
			return BELLE_SIP_STOP;
		});
		belle_sip_main_loop_create_cpp_timeout(  mMainLoop
			, func
			, 0
			, "OnAuthListener to mainthread");
	}

	virtual void processResponse(AuthDbResult result, std::string user) {
		if (result == AuthDbResult::PASSWORD_FOUND) {
			// result is a phone alias if (and only if) user is not the same as the entity user
			bool isPhone = (strcmp(user.c_str(), belle_sip_uri_get_user(mInfo->getEntity())) != 0);
			if (isPhone) {
				// change contact accordingly
				belle_sip_uri_t *uri = BELLE_SIP_URI(belle_sip_object_clone(BELLE_SIP_OBJECT(mInfo->getEntity())));
				belle_sip_parameters_t* params=BELLE_SIP_PARAMETERS(uri);
				belle_sip_parameters_remove_parameter(params, "user");
				belle_sip_uri_set_user(uri, user.c_str());
				char *contact_as_string = belle_sip_uri_to_string(uri);
				belle_sip_object_unref(uri);
				SLOGD << __FILE__ << ": " << "Found user " << user << " for phone "
					<< belle_sip_uri_get_user(mInfo->getEntity()) << ", adding contact " << contact_as_string << " presence information";
				mInfo->setDefaultElement(contact_as_string);
				belle_sip_free(contact_as_string);
			} else {
				SLOGD << __FILE__ << ": " << "Found user " << user << ", adding presence information";
				mInfo->setDefaultElement();
			}
		} else {
			SLOGD << __FILE__ << ": " << "Could not find user " << user << ".";
		}
		delete this;
	}
private:
	belle_sip_main_loop_t *mMainLoop;
	const std::shared_ptr<PresentityPresenceInformation> mInfo;
};

void PresenceLongterm::onNewPresenceInfo(const std::shared_ptr<PresentityPresenceInformation>& info) const {
	const belle_sip_uri_t* uri = info->getEntity();
	SLOGD << __FILE__ << ": " << "New presence info for " << belle_sip_uri_get_user(uri) << ", checking if this user is already registered";
	AuthDbBackend::get()->getUserWithPhone(belle_sip_uri_get_user(info->getEntity()), belle_sip_uri_get_host(info->getEntity()), new OnAuthListener(mMainLoop, info));
}
