/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL.

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

#include "flexisip/sofia-wrapper/sdp-parser.hh"

#include <ostream>

namespace sofiasip {

using namespace std;

SdpParser::UniquePtr SdpParser::parse(string_view msg, Flags flags) {
	return UniquePtr(parse(nullptr, msg, flags));
}
SdpParser& SdpParser::parse(su_home_t& home, string_view msg, Flags flags) {
	return *parse(&home, msg, flags);
}

SdpParser* SdpParser::parse(su_home_t* home, string_view msg, Flags flags) {
	static_assert(
	    sizeof(SdpParser) == 1,
	    "You cannot add members to an SdpParser. It is meant as a ghost type that will be cast from an opaque type.");
	return reinterpret_cast<SdpParser*>(::sdp_parse(home, msg.data(), msg.size(), static_cast<int>(flags)));
}

variant<reference_wrapper<SdpSession>, SdpParsingError> SdpParser::session() {
	auto* maybeSession = SdpSession::wrap(::sdp_session(toSofia()));
	if (maybeSession == nullptr) {
		return SdpParsingError{::sdp_parsing_error(toSofia())};
	}

	return *maybeSession;
}

void SdpParser::Deleter::operator()(SdpParser* ptr) noexcept {
	if (ptr) ::sdp_parser_free(ptr->toSofia());
}

::sdp_parser SdpParser::toSofia() {
	return reinterpret_cast<::sdp_parser>(this);
}

SdpSession* SdpSession::wrap(::sdp_session_t* raw) {
	static_assert(sizeof(SdpSession) == sizeof(*raw),
	              "You cannot add members to an SdpSession. It is meant as a transparent wrapper.");
	return static_cast<SdpSession*>(raw);
}

SdpMedia* SdpMedia::wrap(::sdp_media_t* raw) {
	static_assert(sizeof(SdpMedia) == sizeof(*raw),
	              "You cannot add members to an SdpMedia. It is meant as a transparent wrapper.");
	return static_cast<SdpMedia*>(raw);
}

SdpAttribute* SdpAttribute::wrap(::sdp_attribute_t* raw) {
	static_assert(sizeof(SdpAttribute) == sizeof(*raw),
	              "You cannot add members to an SdpAttribute. It is meant as a transparent wrapper.");
	return static_cast<SdpAttribute*>(raw);
}

SdpMediaList SdpSession::medias() {
	return SdpMediaList(sdp_media);
}

SdpMediaAttributeFilter::Iterator::Iterator(::sdp_attribute_t* ptr, const char* name)
    : mName(name), mPtr(::sdp_attribute_find(ptr, mName)) {
}

SdpMediaAttributeFilter::Iterator& SdpMediaAttributeFilter::Iterator::operator++() {
	mPtr = ::sdp_attribute_find(mPtr->a_next, mName);
	return *this;
}

ostream& operator<<(ostream& stream, const SdpParsingError& err) {
	return stream << "SdpParsingError('" << static_cast<const string_view&>(err) << "')";
}

}; // namespace sofiasip
