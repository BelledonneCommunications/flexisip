/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include "xml/data-model.hh"

namespace flexisip {

class XsdUtils {
public:
	static time_t toTimeT(const Xsd::DataModel::Timestamp_t& xsdT) noexcept {
		tm tm = {0};
		tm.tm_year = (xsdT.year() - 1900);
		tm.tm_mon = (xsdT.month() - 1);
		tm.tm_mday = xsdT.day();
		tm.tm_hour = xsdT.hours();
		tm.tm_min = xsdT.minutes();
		tm.tm_sec = static_cast<int>(xsdT.seconds());
		if (xsdT.zone_present()) {
			tm.tm_hour += xsdT.zone_hours();
			tm.tm_min += xsdT.zone_minutes();
		}

		return timegm(&tm);
	}
};

bool operator<(const Xsd::DataModel::Timestamp_t& lhs, const Xsd::DataModel::Timestamp_t& rhs) {
	auto timeL = XsdUtils::toTimeT(lhs);
	auto timeR = XsdUtils::toTimeT(rhs);
	return timeL < timeR;
}
bool operator>(const Xsd::DataModel::Timestamp_t& lhs, const Xsd::DataModel::Timestamp_t& rhs) {
	return rhs < lhs;
}
bool operator<=(const Xsd::DataModel::Timestamp_t& lhs, const Xsd::DataModel::Timestamp_t& rhs) {
	return !(lhs > rhs);
}
bool operator>=(const Xsd::DataModel::Timestamp_t& lhs, const Xsd::DataModel::Timestamp_t& rhs) {
	return !(lhs < rhs);
}

} // namespace flexisip
