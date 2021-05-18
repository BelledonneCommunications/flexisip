/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2010-2021  Belledonne Communications SARL, All rights reserved.

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

#pragma once

#include "http-message.hh"

namespace flexisip {

/**
 * Representation of a HTTP response, here this is simply a HTTP message with a status code.
 * Be careful the way the HttpResponse::getStatusCode method work only fit HTTP/2 response.
 */
class HttpResponse : public HttpMessage {
public:
	int getStatusCode() const;
};

} /* namespace flexisip */
