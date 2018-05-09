/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2018  Belledonne Communications SARL, All rights reserved.

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

#ifndef plugin_hh
#define plugin_hh

#include "flexisip_gitversion.h"
#include "module.hh"

// =============================================================================

#ifndef FLEXISIP_GIT_VERSION
	#define FLEXISIP_GIT_VERSION "undefined"
#endif // ifndef FLEXISIP_GIT_VERSION

#ifdef WIN32
	#define FLEXISIP_PLUGIN_EXPORT __declspec(dllexport)
#else
	#define FLEXISIP_PLUGIN_EXPORT
#endif // ifdef WIN32

struct PluginInfo {
	const char *className;
	const char *name;
	int version;
	const char *apiVersion;
};

#define FLEXISIP_DECLARE_PLUGIN(CLASS, NAME, VERSION) \
	static_assert(std::is_base_of<Module, CLASS>::value, "Flexisip plugin must be derived from Module class."); \
	extern "C" { \
		FLEXISIP_PLUGIN_EXPORT CLASS *flexisipCreatePlugin(Agent *agent) { \
			return new CLASS(agent); \
		} \
		FLEXISIP_PLUGIN_EXPORT const PluginInfo flexisipPluginInfo = { \
			#CLASS, \
			NAME, \
			VERSION, \
			FLEXISIP_GIT_VERSION \
		}; \
	}

#endif // plugin_hh
