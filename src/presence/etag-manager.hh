/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2014  Belledonne Communications SARL.
 
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

#ifndef ETAG_MANAGER_HH_
#define ETAG_MANAGER_HH_
#include "string"
#include "flexisip-exception.hh"
namespace flexisip {
class PresentityPresenceInformation;
class EtagManager {

public:
	virtual void invalidateETag(const string& eTag) = 0;
	virtual void modifyEtag(const string& oldEtag, const string& newEtag) throw (FlexisipException)=0;
	virtual void addEtag(const std::shared_ptr<PresentityPresenceInformation>&  info,const string& etag) throw (FlexisipException)=0;
};
}
#endif /* ETAG_MANAGER_HH_ */
