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

#include <dlfcn.h>

#include "plugin-loader.hh"
#include "plugin.hh"

// =============================================================================

using namespace std;

// -----------------------------------------------------------------------------

class Library {
public:
	Library(void *_sysLibrary = nullptr) : sysLibrary(_sysLibrary) {}
	~Library() {
		if (sysLibrary)
			dlclose(sysLibrary);
	}

	void *sysLibrary = nullptr;
};
typedef shared_ptr<Library> SharedLibrary;

// -----------------------------------------------------------------------------

class PluginLoaderPrivate {
public:
	Agent *agent = nullptr;

	string filename;
	string error;

	shared_ptr<Library> library;

	Module *module = nullptr;
	Private::PluginPrivate *pPlugin = nullptr;

	void setDlerror () {
		const char *dlError = dlerror();
		error = dlError ? dlError : "Unknown";
	}
};

// -----------------------------------------------------------------------------

namespace Private {
	class PluginPrivate {
	public:
		PluginLoader *loader = nullptr;
		SharedLibrary library;
	};

	Plugin::Plugin(PluginPrivate &p) : mPrivate(&p) {}

	Plugin::~Plugin() {
		// Invalid plugin instance in loader.
		if (mPrivate->loader) {
			PluginLoaderPrivate *pLoader = mPrivate->loader->mPrivate;
			pLoader->module = nullptr;
			pLoader->pPlugin = nullptr;
		}

		delete mPrivate;
	}
}

// -----------------------------------------------------------------------------

PluginLoader::PluginLoader(Agent *agent) : mPrivate(new PluginLoaderPrivate) {
	mPrivate->agent = agent;
}

PluginLoader::PluginLoader(Agent *agent, const string &filename) : PluginLoader(agent) {
	mPrivate->filename = filename;
}

PluginLoader::~PluginLoader() {
	// Invalid loader reference in plugin.
	if (mPrivate->pPlugin)
		mPrivate->pPlugin->loader = nullptr;

	delete mPrivate;
}

const string &PluginLoader::getFilename() const {
	return mPrivate->filename;
}

void PluginLoader::setFilename(const string &filename) {
	unload();
	mPrivate->filename = filename;
}

bool PluginLoader::isLoaded() const {
	return mPrivate->library.get();
}

bool PluginLoader::load() {
	if (isLoaded())
		return true;

	void *sysLibrary = dlopen(mPrivate->filename.c_str(), RTLD_LAZY);
	if (!sysLibrary) {
		mPrivate->setDlerror();
		return false;
	}

	PluginInfo *info = static_cast<PluginInfo *>(dlsym(sysLibrary, "__flexisipPluginInfo"));
	if (!info) {
		mPrivate->setDlerror();
		dlclose(sysLibrary);
		return false;
	}

	if (strcmp(info->apiVersion, FLEXISIP_PLUGIN_API_VERSION)) {
		mPrivate->error = "Incompatible plugin API. Expected `" FLEXISIP_PLUGIN_API_VERSION "`, got `";
		mPrivate->error.append(info->apiVersion);
		mPrivate->error.append("`.");
		dlclose(sysLibrary);
		return false;
	}

	SLOGI << "Plugin loaded with success! " << *info;

	mPrivate->error.clear();
	mPrivate->library = make_shared<Library>(sysLibrary);
	return true;
}

bool PluginLoader::unload() {
	mPrivate->library.reset();

	mPrivate->module = nullptr;
	if (mPrivate->pPlugin) {
		mPrivate->pPlugin->loader = nullptr;
		mPrivate->pPlugin = nullptr;
	}

	return true;
}

Module *PluginLoader::get() {
	if (!mPrivate->module) {
		if (load()) {
			Module *(*createPlugin)(Private::PluginPrivate &p, Agent *agent);
			*reinterpret_cast<void **>(&createPlugin) = dlsym(mPrivate->library->sysLibrary, "__flexisipCreatePlugin");
			if (!createPlugin)
				SLOGE << "Unable to get plugin. Create symbol not found.";
			else {
				Private::PluginPrivate *pPlugin = new Private::PluginPrivate;
				pPlugin->loader = this;
				pPlugin->library = mPrivate->library;
				mPrivate->module = createPlugin(*pPlugin, mPrivate->agent);
				mPrivate->pPlugin = pPlugin;
			}
		}
	}
	return mPrivate->module;
}

const string &PluginLoader::getError() const {
	return mPrivate->error;
}
