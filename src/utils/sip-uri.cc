#include <cstring>
#include <sstream>
#include <stdexcept>

#include "sip-uri.hh"

using namespace std;

namespace flexisip {

SipUri::SipUri(const std::string &str) {
	try {
		su_home_init(&_home);
		_url = url_make(&_home, str.c_str());
		if (_url == nullptr) throw invalid_argument("parsing failed");
		if (_url->url_scheme == nullptr) throw invalid_argument("no scheme found");
		if (strcmp(_url->url_scheme, "sip") != 0 && strcmp(_url->url_scheme, "sips") != 0) {
			ostringstream os;
			os << "invalid scheme (" << _url->url_scheme << ")";
			throw invalid_argument(os.str());
		}
		if (_url->url_host == nullptr || _url->url_host[0] == '\0') {
			throw invalid_argument("no host found");
		}
	} catch (...) {
		su_home_deinit(&_home);
		throw;
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
