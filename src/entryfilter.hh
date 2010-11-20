/*
	Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010  Belledonne Communications SARL.

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

#ifndef entryfilter_hh
#define entryfilter_hh

#include <list>
#include <string>

#include "agent.hh"

/**
 * The goal of this object is to filter SIP message that enter into a module.
 **/
class EntryFilter{
	public:
		virtual void loadConfig(const ConfigArea &vmodule_config){
		}
		virtual bool canEnter(sip_t *sip)=0;
};

class ConfigEntryFilter : public EntryFilter {
	public:
		ConfigEntryFilter();
		virtual ~ConfigEntryFilter();
		virtual void loadConfig(const ConfigArea &vmodule_config);
		virtual bool canEnter(sip_t *sip);
	private:
		std::list<std::string> mDomains;
		bool mEnabled;
};


#endif
