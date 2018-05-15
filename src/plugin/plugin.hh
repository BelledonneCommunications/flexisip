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

// -----------------------------------------------------------------------------
// Private API.
// -----------------------------------------------------------------------------

#ifndef FLEXISIP_GIT_VERSION
	#define FLEXISIP_GIT_VERSION "undefined"
#endif // ifndef FLEXISIP_GIT_VERSION

#ifdef WIN32
	#define FLEXISIP_PLUGIN_EXPORT __declspec(dllexport)
#else
	#define FLEXISIP_PLUGIN_EXPORT
#endif // ifdef WIN32

namespace Private {
	class PluginPrivate;

	class Plugin {
	public:
		Plugin(PluginPrivate &p);
		virtual ~Plugin();

	private:
		PluginPrivate *mPrivate;

		FLEXISIP_DISABLE_COPY(Plugin);
	};
}

// -----------------------------------------------------------------------------
// Public API.
// -----------------------------------------------------------------------------

#define FLEXISIP_PLUGIN_API_VERSION FLEXISIP_GIT_VERSION

struct PluginInfo {
	const char *className;
	const char *name;
	int version;
	const char *apiVersion;
};

inline std::ostream &operator<< (std::ostream &os, const PluginInfo &info) {
	os << "Plugin info:" << std::endl <<
		"  Name: " << info.name << std::endl <<
		"  Class Name: " << info.className << std::endl <<
		"  Version: " << info.version << std::endl <<
		"  Api Version: " << info.apiVersion;
	return os;
}

#define FLEXISIP_DECLARE_PLUGIN(CLASS, NAME, VERSION) \
	static_assert(std::is_base_of<Module, CLASS>::value, "Flexisip plugin must be derived from Module class."); \
	extern "C" { \
		FLEXISIP_PLUGIN_EXPORT Module *__flexisipCreatePlugin(Private::PluginPrivate &p, Agent *agent) { \
			class UserPlugin : public CLASS, public Private::Plugin { \
			public: \
				UserPlugin(Private::PluginPrivate &p, Agent *agent) : CLASS(agent), Plugin(p) {} \
			}; \
			return new UserPlugin(p, agent); \
		} \
		FLEXISIP_PLUGIN_EXPORT const PluginInfo __flexisipPluginInfo = { \
			#CLASS, \
			NAME, \
			VERSION, \
			FLEXISIP_PLUGIN_API_VERSION \
		}; \
	}

#endif // plugin_hh
