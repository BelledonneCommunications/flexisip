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

#include "inject-context.hh"

#include "fork-context/fork-context.hh"

using namespace std;
using namespace std::chrono;
using namespace flexisip;

milliseconds InjectContext::sMaxRequestRetentionTime = 30s;

bool InjectContext::isEqual(const std::shared_ptr<ForkContext>& fork) const {
	return mFork->isEqual(fork);
}

bool InjectContext::isExpired() const {
	return (mCreationDate + sMaxRequestRetentionTime) < steady_clock::now();
}

void InjectContext::setMaxRequestRetentionTime(milliseconds maxRequestRetentionTime) {
	InjectContext::sMaxRequestRetentionTime = maxRequestRetentionTime;
}