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

#pragma once

#include <dlfcn.h>
#include <string>

#include <flexisip/global.hh>
#include <flexisip/module.hh>

#include "agent.hh"
#include "eventlogs/writers/event-log-writer.hh"

// =============================================================================

namespace flexisip {

class PluginLoaderPrivate;

class PluginLoader {
public:
	PluginLoader();
	PluginLoader(const std::string& filename);
	~PluginLoader();

	const std::string& getFilename() const;
	void setFilename(const std::string& filename);

	bool isLoaded() const;
	bool load();
	bool unload();

	const ModuleInfoBase* getModuleInfo();

	const std::string& getError() const;

private:
	PluginLoaderPrivate* mPrivate;

	FLEXISIP_DISABLE_COPY(PluginLoader);
};

class SharedLibrary {
public:
	SharedLibrary(const std::string& filename, void* library) : mFilename(filename), mLibrary(library) {
	}

	SharedLibrary(SharedLibrary&& other)
	    : mFilename(std::move(other.mFilename)), mLibrary(other.mLibrary), mRefCounter(other.mRefCounter) {
		other.mLibrary = nullptr;
	}

	~SharedLibrary() {
		if (mLibrary) dlclose(mLibrary);
	}

	void ref() {
		++mRefCounter;
	}

	void unref() {
		--mRefCounter;
	}

	bool unload();

	void* get() const {
		return mLibrary;
	}

private:
	std::string mFilename;
	void* mLibrary;

	int mRefCounter;
};

class PluginLoaderPrivate {
public:
	std::string filename;

	SharedLibrary* sharedLibrary = nullptr;

	std::string error;

	int libraryRefCounter = 0;
};

} // namespace flexisip