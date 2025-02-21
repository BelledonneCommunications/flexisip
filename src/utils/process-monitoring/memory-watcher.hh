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

#include <chrono>
#include <filesystem>
#include <optional>
#include <regex>

#include "flexisip/sofia-wrapper/timer.hh"

namespace flexisip::process_monitoring {

class UsedMemory {
public:
	explicit UsedMemory(float memoryAmount) : mAmount(memoryAmount) {};

	friend std::ostream& operator<<(std::ostream& os, const UsedMemory& usedMemory);

private:
	float mAmount;
};

class MemoryWatcher {
public:
	MemoryWatcher(const std::shared_ptr<sofiasip::SuRoot>& root, const std::chrono::seconds& duration);

private:
	static constexpr std::string_view mLogPrefix{"MemoryWatcher - "};

	void logMemoryUsed();
	std::optional<UsedMemory> getUsedMemory();

	const std::filesystem::path mStatusFilePath;
	const std::regex mRegex;
	std::unique_ptr<sofiasip::Timer> mTimer{};
};

} // namespace flexisip::process_monitoring