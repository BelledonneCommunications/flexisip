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

#include <cstddef>
#include <string_view>
#include <variant>

#include "compat/hiredis/async.h"

// Type-safe wrapper interface to redisReply structs
// Please refer to https://redis.io/docs/latest/commands/ to determine which replies a given Redis command can return
namespace flexisip::redis::reply {

class String : public std::string_view {
public:
	using std::string_view::string_view;

	friend std::ostream& operator<<(std::ostream&, const String&);
};
// Human-readable description of an error that occurred when trying to run the command
class Error : public std::string_view {
public:
	using std::string_view::string_view;

	friend std::ostream& operator<<(std::ostream&, const Error&);
};
// The success status of a command that otherwise does not return anything (usually equal to "OK")
class Status : public std::string_view {
public:
	using std::string_view::string_view;

	friend std::ostream& operator<<(std::ostream&, const Status&);
};
// An empty command reply.
// Happens in e.g. `HGET` commands when the target entry is not found.
// https://redis.io/docs/latest/commands/hget/#resp2-reply
// (As of 2024-08-05, `HGET` is the only command we use which may reply `Nil`)
class Nil {
public:
	friend std::ostream& operator<<(std::ostream&, const Nil&);
};
using Integer = decltype(redisReply::integer);
// The session disconnected before being able to get the result of this command.
// Callbacks receiving this reply MUST NOT access memory which would have been freed before the
// redis::Session/RedisClient. The reason being that this reply is also sent to all pending command/subscriptions on
// destruction of the redis::Session (and, consequently, of the RedisClient).
class Disconnected {
public:
	friend std::ostream& operator<<(std::ostream&, const Disconnected&);

	inline bool operator==(const Disconnected&) const noexcept {
		return true;
	}
};

class ArrayOfPairs;

// An array of generic elements.
// This class is iterable and indexable
class Array {
public:
	using Element = std::variant<String, Array, Integer, Status>;

	class Iterator {
	public:
		Iterator(const redisReply* const* ptr) : ptr(ptr) {
		}
		Iterator operator++() {
			++ptr;
			return *this;
		}
		bool operator!=(const Iterator& other) const {
			return ptr != other.ptr;
		}
		Element operator*();

	private:
		const redisReply* const* ptr;
	};

	Array(const redisReply* const* elements, std::size_t count) : mElements(elements), mCount(count) {
	}

	Iterator begin() const {
		return mElements;
	}
	Iterator end() const {
		return mElements + mCount;
	}

	std::size_t size() const {
		return mCount;
	}

	Element operator[](std::size_t) const;

	// Return elements two by two.
	// Useful to parse Redis Hashes which are returned as arrays of key-value pairs
	ArrayOfPairs pairwise() const;

	friend std::ostream& operator<<(std::ostream&, const Array&);

private:
	const redisReply* const* mElements;
	const std::size_t mCount;
};

// A view into a Redis Array reply returning elements two by two
// This class is iterable and indexable
class ArrayOfPairs {
public:
	using Element = Array::Element;
	class Iterator {
	public:
		Iterator(const redisReply* const* ptr) : ptr(ptr) {
		}
		Iterator operator++() {
			ptr += 2;
			return *this;
		}
		bool operator!=(const Iterator& other) const {
			return ptr != other.ptr;
		}
		std::pair<Element, Element> operator*();

	private:
		const redisReply* const* ptr;
	};

	ArrayOfPairs(const redisReply* const* elements, std::size_t count);

	Iterator begin() const {
		return mElements;
	}
	Iterator end() const {
		return mElements + mCount * 2;
	}

	std::size_t size() const {
		return mCount;
	}

	std::pair<Element, Element> operator[](std::size_t) const;

private:
	const redisReply* const* mElements;
	const std::size_t mCount;
};

// Union of types that a Redis command callback may receive as input.
// This is only a view into the underlying redisReply* returned by hiredis. It is UNSAFE to keep around for longer than
// the lifetime of the pointed-to struct. (I.e.: Do not copy out of the callback function, it does *not* own the data)
using Reply = std::variant<String, Array, Integer, Error, Disconnected, Status, Nil>;

// Try to get type-safe view into the redisReply. Throws std::runtime_error if the `redisReply::type` is
// unknown/unimplemented
Reply tryFrom(const redisReply*);

} // namespace flexisip::redis::reply