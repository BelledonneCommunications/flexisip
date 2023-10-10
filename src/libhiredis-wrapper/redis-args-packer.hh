/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
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
