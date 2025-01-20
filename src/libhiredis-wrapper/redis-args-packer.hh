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

#include <initializer_list>
#include <list>
#include <sstream>
#include <string>
#include <vector>

namespace flexisip::redis {

/* Utility struct to create argument vectors to pass to redis, for HSET and HDEL requests for example.*/
class ArgsPacker {
public:
	template <typename... Args>
	ArgsPacker(const std::string& command, Args&&... args) {
		addArg(command);
		(addArg(std::forward<Args>(args)), ...);
	}
	void addPair(const std::string& fieldName, const std::string& value) {
		addArg(fieldName);
		addArg(value);
	}
	void addFieldName(const std::string& fieldName) {
		addArg(fieldName);
	}
	void addArgs(const std::initializer_list<std::string>& args) {
		for (const auto& arg : args) {
			addArg(arg);
		}
	}

	const char* const* getCArgs() const {
		return &mCArgs[0];
	}
	const size_t* getArgSizes() const {
		return &mArgsSize[0];
	}
	size_t getArgCount() const {
		return mCArgs.size();
	}
	std::string toString() const {
		std::ostringstream os{};
		os << *this;
		return os.str();
	}
	const std::string& command() const {
		return mArgs.front();
	}

	friend std::ostream& operator<<(std::ostream& out, const ArgsPacker& args) {
		out << "redis::ArgsPacker(";
		for (const auto& arg : args.mArgs) {
			out << arg << " ";
		}
		out << ")";
		return out;
	}

private:
	void addArg(const std::string& arg) {
		mArgs.emplace_back(arg);
		mCArgs.emplace_back(mArgs.back().c_str()); // The C string pointer is held within mArgs
		mArgsSize.push_back(arg.size());
	}

	std::list<std::string> mArgs;
	std::vector<const char*> mCArgs;
	std::vector<size_t> mArgsSize;
};

} // namespace flexisip::redis