/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024  Belledonne Communications SARL, All rights reserved.

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

#include <flexisip/flexisip-version.h>
#include <flexisip/module.hh>

#ifndef FLEXISIP_GIT_VERSION
#define FLEXISIP_GIT_VERSION "undefined"
#endif // ifndef FLEXISIP_GIT_VERSION

#define FLEXISIP_PLUGIN_API_VERSION FLEXISIP_GIT_VERSION

#ifdef WIN32
#define FLEXISIP_PLUGIN_EXPORT extern "C" __declspec(dllexport)
#else
#define FLEXISIP_PLUGIN_EXPORT extern "C"
#endif // ifdef WIN32

namespace flexisip {

struct PluginInfo {
	const char* className;
	const char* name;
	int version;
	const char* apiVersion;
};

inline std::ostream& operator<<(std::ostream& os, const PluginInfo& info) {
	os << "Plugin info:" << std::endl
	   << "  Name: " << info.name << std::endl
	   << "  Class Name: " << info.className << std::endl
	   << "  Version: " << info.version << std::endl
	   << "  Api Version: " << info.apiVersion;
	return os;
}

#define FLEXISIP_DECLARE_PLUGIN(MODULE_INFO, NAME, VERSION)                                                            \
	static_assert(std::is_base_of<ModuleInfoBase, decltype(MODULE_INFO)>::value,                                       \
	              "Flexisip plugin must be derived from ModuleInfoBase class.");                                       \
	FLEXISIP_PLUGIN_EXPORT const ModuleInfoBase* __flexisipGetPluginModuleInfo() {                                     \
		return &MODULE_INFO;                                                                                           \
	}                                                                                                                  \
	FLEXISIP_PLUGIN_EXPORT const PluginInfo __flexisipPluginInfo = {#MODULE_INFO, NAME, VERSION,                       \
	                                                                FLEXISIP_PLUGIN_API_VERSION};

} // namespace flexisip
