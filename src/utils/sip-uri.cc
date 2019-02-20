#include <sstream>
#include <stdexcept>

#include "sip-uri.hh"

using namespace std;

namespace flexisip {

SipUri::SipUri(const std::string &str) {
	su_home_init(&_home);
	_url = url_make(&_home, _urlAsStr.c_str());
	if (_url == nullptr) {
		su_home_deinit(&_home);
		ostringstream os;
		os << _urlAsStr << " is not a valid SIP URI";
		throw invalid_argument(os.str());
	}
}

SipUri::~SipUri() {
	su_home_deinit(&_home);
}

const std::string &SipUri::str() const {
	if (_urlAsStr.empty()) {
		su_home_t home;
		su_home_init(&home);
		_urlAsStr = url_as_string(&home, _url);
		su_home_deinit(&home);
	}
	return _urlAsStr;
}

}
