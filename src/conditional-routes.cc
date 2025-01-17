/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include "conditional-routes.hh"

#include <fstream>

using namespace ::std;

namespace flexisip {

sip_route_t* ConditionalRouteMap::buildRoute(const string& route) {
	sip_route_t* sipRoute = sip_route_make(mHome.home(), route.c_str());
	if (!sipRoute) {
		throw invalid_argument(string("Invalid route: '") + route + string("'"));
	}
	if (!url_has_param(sipRoute->r_url, "lr")) {
		url_param_add(mHome.home(), sipRoute->r_url, "lr");
	}
	return sipRoute;
}

void ConditionalRouteMap::loadConfig(const std::string& path) {
	ifstream ifs;
	ostringstream contentstream;
	size_t currentPos;
	
	SLOGD << "Parsing conditional routing configuration file '" << path << "'";
	ifs.open(path);
	if (!ifs.good()) throw runtime_error(string("Could not open ") + path);

	contentstream << ifs.rdbuf();
	string content = contentstream.str();

	bool inAComment = false;

	for (currentPos = 0; currentPos < content.size(); ++currentPos) {
		string route;
		sip_route_t* sipRoute;
		size_t it;

		if (content[currentPos] == '#') {
			inAComment = true;
			continue;
		} else if (inAComment) {
			if (content[currentPos] == '\n') {
				inAComment = false;
			}
			continue;
		} else if (content[currentPos] == ' ' || content[currentPos] == '\t' || content[currentPos] == '\n') {
			continue;
		}
		istringstream istr(content.substr(currentPos));
		istr >> route;

		if (route.empty()) continue;
		sipRoute = buildRoute(route);
		currentPos += route.size();

		/* skip spaces or tab */
		while (content[currentPos] == ' ' || content[currentPos] == '\t')
			++currentPos;
		/* now extract the condition part*/
		ostringstream rulestream;

		for (it = currentPos; it < content.size(); ++it) {
			if (content[it] == '#') {
				inAComment = true;
			} else if (content[it] == '\n') {
				inAComment = false;
				if (it + 1 < content.size()) {
					switch (content[it + 1]) {
						case ' ':
						case '\t':
							continue;
							break;
						default:
							break;
					}
					break; // break for loop.
				} else {
					break; // end of file, break for loop too.
				}
			}
			if (!inAComment) rulestream << content[it];
		}
		currentPos = it;
		string rule(rulestream.str());
		SLOGD << "Got route='" << route << "' condition='" << rule << "'";
		if (rule.empty()) {
			throw invalid_argument(string("No condition provided for route '" + route + string("'")));
		}
		if (rule == "*") {
			/* the wildcard is interpreted as a always true condition */
			rule.resize(0); /* the void expression is true in SipBooleanExpression */
		}
		auto expr = SipBooleanExpressionBuilder::get().parse(rule);
		if (!expr) {
			throw invalid_argument(string("Invalid expression: '") + rule + string("'"));
		}
		mRoutes.push_back(make_pair(sipRoute, expr));
	}
    SLOGD << "Done parsing " << path;
}

const sip_route_t* ConditionalRouteMap::resolveRoute(const std::shared_ptr<MsgSip>& msgsip) const {
	return resolveRoute(*msgsip);
}

const sip_route_t* ConditionalRouteMap::resolveRoute(const MsgSip& msgsip) const {
	return resolveRoute(*msgsip.getSip());
}

const sip_route_t* ConditionalRouteMap::resolveRoute(const sip_t& sip) const {
	for (const auto& p : mRoutes) {
		if (p.second->eval(sip)) return p.first;
	}
	return nullptr;
}

} // namespace flexisip