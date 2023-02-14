/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

#include "request.hh"
#include "service.hh"

namespace flexisip {
namespace pushnotification {

class Service;

class Client {
public:
	Client(const Service* service = nullptr) : mService{service} {};
	virtual ~Client() = default;
	virtual void sendPush(const std::shared_ptr<Request>& req) = 0;
	virtual bool isIdle() const noexcept = 0;

	virtual void setRequestTimeout([[maybe_unused]] std::chrono::seconds requestTimeout){};

protected:
	void incrSentCounter();
	void incrFailedCounter();

private:
	const Service* mService;

	friend class Service;
};

} // namespace pushnotification
} // namespace flexisip
