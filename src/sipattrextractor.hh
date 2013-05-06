/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2012  Belledonne Communications SARL.

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

#ifndef SIPATTREXTRACTOR_HH
#define SIPATTREXTRACTOR_HH

#include <string>
#include <memory>

#ifndef NO_SOFIA
#include <sofia-sip/sip.h>
#endif

class SipAttributes {
public:
#ifdef NO_SOFIA
	SipAttributes(std::string &attributes);
#else
	SipAttributes(sip_t *sip) : sip(sip){};
private:
	sip_t *sip;
#endif
public:
	~SipAttributes(){};

	
	std::string get(const std::string &arg) const;
	
	std::string getOrEmpty(const std::string &arg) const{
		if (arg == "method_or_status") {
			std::string method=getOrEmpty("request.mn");
			if (!method.empty()) return method;
			return getOrEmpty("status.code");
		}

		try {
			return get(arg);
		} catch (...) {
			return "";
		}
	}
	bool isTrue(const std::string &arg) const;
};



#endif
