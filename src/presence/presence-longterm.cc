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
		belle_sip_source_t *timer = belle_sip_main_loop_create_cpp_timeout(  mMainLoop
			, func
			, 0
			, "OnAuthListener to mainthread");
	}

	virtual void processResponse(AuthDbResult result, std::string passwd) {
		if (result == AuthDbResult::PASSWORD_FOUND) {
			SLOGD << "Found user " << belle_sip_uri_get_user(mInfo->getEntity()) << ", adding presence information";
			mInfo->setDefaultElement();
		}
		delete this;
	}
private:
	belle_sip_main_loop_t *mMainLoop;
	const std::shared_ptr<PresentityPresenceInformation> mInfo;
};

void PresenceLongterm::onNewPresenceInfo(const std::shared_ptr<PresentityPresenceInformation>& info) const {
	const belle_sip_uri_t* uri = info->getEntity();
	AuthDbBackend::get()->getPassword(belle_sip_uri_get_user(uri), belle_sip_uri_get_host(uri), belle_sip_uri_get_user(uri), new OnAuthListener(mMainLoop, info));
}

