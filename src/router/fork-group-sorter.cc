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

#include "fork-group-sorter.hh"

#include <sstream>

using namespace std;
using namespace sofiasip;

namespace flexisip {

void ForkGroupSorter::makeGroups() {
	Home home{};
	// First step, eliminate adjacent contacts, they cannot be factorized.
	for (auto it = mAllContacts.begin(); it != mAllContacts.end();) {
		if ((*it).second->mPath.size() < 2) {
			// This is a "direct" destination, nothing to do.
			mDestinations.emplace_back(ForkDestination{
			    .targetUris = "",
			    .sipContact = (*it).first,
			    .extendedContact = (*it).second,
			});
			it = mAllContacts.erase(it);
		} else ++it;
	}
	// Second step, form groups with non-adjacent contacts.
	for (auto it = mAllContacts.begin(); it != mAllContacts.end();) {
		list<pair<sip_contact_t*, shared_ptr<ExtendedContact>>>::iterator sameDestinationIt;
		ForkDestination dest;
		ostringstream targetUris;
		bool foundGroup = false;

		dest.sipContact = (*it).first;
		dest.extendedContact = (*it).second;
		targetUris << "<" << *dest.extendedContact->toSofiaUrlClean(home.home()) << ">";
		url_t* url = url_make(home.home(), (*it).second->mPath.back().c_str());
		// Remove it and now search for other contacts that have the same route.
		it = mAllContacts.erase(it);
		while ((sameDestinationIt = findDestination(url)) != mAllContacts.end()) {
			targetUris << ", <" << *(*sameDestinationIt).second->toSofiaUrlClean(home.home()) << ">";
			mAllContacts.erase(sameDestinationIt);
			foundGroup = true;
		}
		if (foundGroup) {
			// A group was formed.
			LOGD << "A group with targetUris " << targetUris.str() << " was formed";
			dest.targetUris = targetUris.str();
			it = mAllContacts.begin();
		}
		mDestinations.emplace_back(dest);
	}
}

void ForkGroupSorter::makeDestinations() {
	for (auto it = mAllContacts.begin(); it != mAllContacts.end(); ++it) {
		mDestinations.emplace_back(ForkDestination{
		    .targetUris = "",
		    .sipContact = (*it).first,
		    .extendedContact = (*it).second,
		});
	}
}

const std::list<ForkDestination>& ForkGroupSorter::getDestinations() const {
	return mDestinations;
}

ForkGroupSorter::ForkContacts::iterator ForkGroupSorter::findDestination(const url_t* url) {
	Home home{};
	for (auto it = mAllContacts.begin(); it != mAllContacts.end(); ++it) {
		url_t* it_route = url_make(home.home(), (*it).second->mPath.back().c_str());
		if (url_cmp(it_route, url) == 0) {
			return it;
		}
	}
	return mAllContacts.end();
}

} // namespace flexisip