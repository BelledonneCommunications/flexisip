#include "utils.hh"
#include "../conference/conference-server.hh"
#include <flexisip/registrardb.hh>

namespace flexisip {

namespace RegistrationEvent {


string Utils::getDeviceName(const shared_ptr<ExtendedContact> &ec) {
	const string &userAgent = ec->getUserAgent();
	size_t begin = userAgent.find("(");
	string deviceName;
	if (begin != string::npos) {
		size_t end = userAgent.find(")", begin);
		size_t openingParenthesis = userAgent.find("(", begin + 1);
		while (openingParenthesis != string::npos && openingParenthesis < end) {
			openingParenthesis = userAgent.find("(", openingParenthesis + 1);
			end = userAgent.find(")", end + 1);
		}
		if (end != string::npos){
			deviceName = userAgent.substr(begin + 1, end - (begin + 1));
		}
	}
	return deviceName;
}

}

}