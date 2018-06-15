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
#include <unordered_map>

#include "plugin-loader.hh"
#include "plugin.hh"

// =============================================================================

using namespace std;

// -----------------------------------------------------------------------------
// Low API to open library.
// -----------------------------------------------------------------------------

static string getDlerror () {
	const char *dlError = dlerror();
	return dlError ? dlError : "Unknown";
}

static void *openLibrary(const string &filename, string &error) {
	void *library = dlopen(filename.c_str(), RTLD_LAZY);
	if (!library) {
		error = getDlerror();
		return nullptr;
	}

	PluginInfo *info = static_cast<PluginInfo *>(dlsym(library, "__flexisipPluginInfo"));
	if (!info) {
		error = getDlerror();
		dlclose(library);
		return nullptr;
	}

	if (strcmp(info->apiVersion, FLEXISIP_PLUGIN_API_VERSION)) {
		error = "Incompatible plugin API. Expected `" FLEXISIP_PLUGIN_API_VERSION "`, got `";
		error.append(info->apiVersion);
		error.append("`.");
		dlclose(library);
		return nullptr;
	}

	error.clear();
	return library;
}

// -----------------------------------------------------------------------------
// SharedLibrary between each PluginLoader.
// -----------------------------------------------------------------------------

class SharedLibrary {
public:
	SharedLibrary(const string &filename, void *library) : mFilename(filename), mLibrary(library) {}

	// Workaround for older gcc versions.
	// Move ctor is not correctly supported with std::pair on older versions of gcc.
	#if __GNUC__ < 5
	SharedLibrary(
		const SharedLibrary &other
	) : module(other.module), mFilename(move(other.mFilename)), mLibrary(other.mLibrary), mRefCounter(other.mRefCounter) {
		SharedLibrary &self = const_cast<SharedLibrary &>(other);
		self.module = nullptr;
		self.mLibrary = nullptr;
	}
	#else
	SharedLibrary(
		SharedLibrary &&other
	) : module(other.module), mFilename(move(other.mFilename)), mLibrary(other.mLibrary), mRefCounter(other.mRefCounter) {
		other.module = nullptr;
		other.mLibrary = nullptr;
	}
	#endif // if __GNUC__ < 5

	~SharedLibrary() {
		if (module)
			delete module;
		if (mLibrary)
			dlclose(mLibrary);
	}

	void ref() {
		++mRefCounter;
	}

	void unref() {
		--mRefCounter;
	}

	bool unload();

	void *get() const { return mLibrary; }

	Module *module = nullptr;

private:
	string mFilename;
	void *mLibrary;

	int mRefCounter;
};

namespace {
	unordered_map<string, SharedLibrary> LoadedLibraries;
}

bool SharedLibrary::unload() {
	if (--mRefCounter == 1) {
		LoadedLibraries.erase(mFilename);
		return true;
	}
	return false;
}

static SharedLibrary *getOrCreateSharedLibrary(const string &filename, string &error) {
	SharedLibrary *sharedLibrary;

	auto it = LoadedLibraries.find(filename);
	if (it != LoadedLibraries.end()) {
		sharedLibrary = &it->second;
		error.clear();
	} else {
		void *library = openLibrary(filename, error);
		if (library)
			sharedLibrary = &LoadedLibraries.insert(make_pair(filename, SharedLibrary(filename, library))).first->second;
		else
			return nullptr;
	}

	return sharedLibrary;
}

// -----------------------------------------------------------------------------
// PluginLoader.
// -----------------------------------------------------------------------------

class PluginLoaderPrivate {
public:
	Agent *agent = nullptr;
	string filename;

	SharedLibrary *sharedLibrary = nullptr;

	string error;

	int libraryRefCounter = 0;
};

namespace Private {
	Plugin::Plugin(SharedLibrary &sharedLibrary) : mSharedLibrary(&sharedLibrary) {}

	Plugin::~Plugin() {
		mSharedLibrary->module = nullptr;
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
	SharedLibrary *sharedLibrary = mPrivate->sharedLibrary;
	if (sharedLibrary)
		sharedLibrary->unref();

	delete mPrivate;
}

const string &PluginLoader::getFilename() const {
	return mPrivate->filename;
}

void PluginLoader::setFilename(const string &filename) {
	if (mPrivate->sharedLibrary) {
		mPrivate->sharedLibrary->unref();
		mPrivate->sharedLibrary = nullptr;
	}
	mPrivate->filename = filename;
}

bool PluginLoader::isLoaded() const {
	return mPrivate->sharedLibrary;
}

bool PluginLoader::load() {
	if (!mPrivate->sharedLibrary)
		mPrivate->sharedLibrary = getOrCreateSharedLibrary(mPrivate->filename, mPrivate->error);

	if (mPrivate->sharedLibrary) {
		++mPrivate->libraryRefCounter;
		mPrivate->sharedLibrary->ref();
		return true;
	}

	return false;
}

bool PluginLoader::unload() {
	if (!mPrivate->sharedLibrary)
		return false;

	--mPrivate->libraryRefCounter;
	bool unloaded = mPrivate->sharedLibrary->unload();
	if (!mPrivate->libraryRefCounter)
		mPrivate->sharedLibrary = nullptr;

	return unloaded;
}

Module *PluginLoader::get() {
	if (!mPrivate->sharedLibrary && !load())
		return nullptr;

	SharedLibrary *sharedLibrary = mPrivate->sharedLibrary;
	if (sharedLibrary->module)
		return sharedLibrary->module;

	Module *(*createPlugin)(Agent *agent, SharedLibrary *sharedLibrary);
	*reinterpret_cast<void **>(&createPlugin) = dlsym(mPrivate->sharedLibrary->get(), "__flexisipCreatePlugin");
	if (!createPlugin)
		mPrivate->error = "Unable to get plugin. CreatePlugin symbol not found.";
	else
		sharedLibrary->module = createPlugin(mPrivate->agent, sharedLibrary);

	return sharedLibrary->module;
}

const ModuleInfoBase *PluginLoader::getModuleInfo() {
	if (load()) {
		const ModuleInfoBase *(*getPluginModuleInfo)();
		*reinterpret_cast<void **>(&getPluginModuleInfo) = dlsym(mPrivate->sharedLibrary->get(), "__flexisipGetPluginModuleInfo");
		if (!getPluginModuleInfo)
			mPrivate->error = "Unable to get plugin. GetPluginModuleInfo symbol not found.";
		else
			return getPluginModuleInfo();
	}
	return nullptr;
}

const string &PluginLoader::getError() const {
	return mPrivate->error;
}
