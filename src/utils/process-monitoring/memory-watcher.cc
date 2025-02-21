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

#include "memory-watcher.hh"

#include <fstream>

#include "exceptions/bad-configuration.hh"
#include "flexisip/flexisip-version.h"
#include "flexisip/logmanager.hh"

using namespace std;

namespace flexisip::process_monitoring {

static constexpr float MiB = 1024.f;
static constexpr float GiB = 1024.f * 1024.f;

std::ostream& operator<<(std::ostream& os, const UsedMemory& usedMemory) {
	float readableSize;
	std::string unit;
	if (usedMemory.mAmount < MiB) {
		readableSize = usedMemory.mAmount;
		unit = "KiB";
	} else if (usedMemory.mAmount < GiB) {
		readableSize = usedMemory.mAmount / MiB;
		unit = "MiB";
	} else {
		readableSize = usedMemory.mAmount / GiB;
		unit = "GiB";
	}

	return os << readableSize << ' ' << unit;
}

MemoryWatcher::MemoryWatcher(const std::shared_ptr<sofiasip::SuRoot>& root, const std::chrono::seconds& duration)
    : mStatusFilePath("/proc/self/status"), mRegex("VmRSS:[\t ]+([0-9]+) kB") {
	// Check that /proc/self/status exists
	ifstream statusFile(mStatusFilePath);
	if (!statusFile.is_open())
		throw BadConfiguration(
		    "file '" + mStatusFilePath.string() +
		    "' does not exist, memory monitoring is not available, please set memory-usage-log-interval to 0");

	mTimer = make_unique<sofiasip::Timer>(root, duration);
	mTimer->setForEver([this]() { logMemoryUsed(); });
}

void MemoryWatcher::logMemoryUsed() {
	static constexpr string_view flexisipNameAndVersion{"Flexisip-" FLEXISIP_GIT_VERSION};
	auto usedMemory = getUsedMemory();
	if (usedMemory.has_value()) SLOGD << mLogPrefix << flexisipNameAndVersion << ": RAM=" << usedMemory.value();
}

std::optional<UsedMemory> MemoryWatcher::getUsedMemory() {
	ifstream statusFile(mStatusFilePath);
	smatch matches;
	string line;
	if (statusFile.is_open()) {
		while (getline(statusFile, line)) {
			if (regex_search(line, matches, mRegex) && matches.size() > 1) {
				try {
					return UsedMemory{stof(matches[1].str())};
				} catch (invalid_argument& e) {
					SLOGW << mLogPrefix << "Invalid 'VmRSS' value (" << line << ") found in " << mStatusFilePath;
				}
			}
		}
		SLOGW << mLogPrefix << "No 'VmRSS' value found in " << mStatusFilePath;
	} else {
		SLOGW << mLogPrefix << "Failed to open " << mStatusFilePath << ", cannot monitor process memory usage";
	}

	return std::nullopt;
}

} // namespace flexisip::process_monitoring