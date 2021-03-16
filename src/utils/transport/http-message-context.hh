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
#include "http-response.hh"

namespace flexisip {

class HttpMessageContext {
  public:
	using HttpRequest = HttpMessage;
	using OnResponseCb = std::function<void(const std::shared_ptr<HttpRequest>&, const std::shared_ptr<HttpResponse>&)>;
	using OnErrorCb = std::function<void(const std::shared_ptr<HttpRequest>&, int, const std::string&)>;

	HttpMessageContext(const std::shared_ptr<HttpRequest>&& request, const OnResponseCb& onResponseCb,
					   const OnErrorCb& onErrorCb)
		: mRequest{request}, mResponse{std::make_shared<HttpResponse>()}, mOnResponseCb{onResponseCb},
		  mOnErrorCb{onErrorCb} {};

	const OnErrorCb& getOnErrorCb() const {
		return mOnErrorCb;
	}

	const OnResponseCb& getOnResponseCb() const {
		return mOnResponseCb;
	}

	std::shared_ptr<HttpRequest> getRequest() const {
		return mRequest;
	}

	std::shared_ptr<HttpResponse> getResponse() const {
		return mResponse;
	}

  private:
	const std::shared_ptr<HttpRequest> mRequest;
	std::shared_ptr<HttpResponse> mResponse;
	OnResponseCb mOnResponseCb;
	OnErrorCb mOnErrorCb;
};

} /* namespace flexisip */
