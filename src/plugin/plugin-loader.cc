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

#include "plugin-loader.hh"

// =============================================================================

using namespace std;

class PluginLoaderPrivate {
public:
	string filename;
};

PluginLoader::PluginLoader() : mPrivate(new PluginLoaderPrivate) {

}

PluginLoader::PluginLoader(const string &filename) {

}

PluginLoader::~PluginLoader() {
	delete mPrivate;
}

const string &PluginLoader::getFilename() const {
	return mPrivate->filename;
}

void PluginLoader::setFilename() {

}

bool PluginLoader::load() {
	return true;
}

bool PluginLoader::unload() {
	return true;
}

Plugin *PluginLoader::get() {
	return nullptr;
}
