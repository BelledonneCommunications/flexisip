/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "redis-reply.hh"

#include <cstddef>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#include "compat/hiredis/async.h"
#include "utils/variant-utils.hh"

namespace flexisip::redis::reply {
namespace {

Array::Element tryElementFrom(const redisReply* reply) {
	return std::visit(
	    [](auto&& element) -> Array::Element {
		    if constexpr (std::is_constructible_v<Array::Element, decltype(element)>) {
			    return std::move(element);
		    } else {
			    std::ostringstream msg{};
			    msg << "Unexpected type in Redis array element: " << element;
			    throw std::runtime_error{msg.str()};
		    }
	    },
	    tryFrom(reply));
}

} // namespace

Reply tryFrom(const redisReply* reply) {
	if (!reply) return Disconnected{};
	switch (reply->type) {
		case REDIS_REPLY_ERROR: {
			return Error{{reply->str, reply->len}};
		} break;
		case REDIS_REPLY_STATUS: {
			return Status{{reply->str, reply->len}};
		} break;
		case REDIS_REPLY_STRING: {
			return String{{reply->str, reply->len}};
		} break;
		case REDIS_REPLY_INTEGER: {
			return reply->integer;
		} break;
		case REDIS_REPLY_ARRAY: {
			return Array{reply->element, reply->elements};
		} break;
		case REDIS_REPLY_NIL: {
			return Nil{};
		} break;

		default:
			throw std::runtime_error{"Unimplemented Redis reply type: " + std::to_string(reply->type)};
			break;
	}
}

Array::Element Array::operator[](std::size_t index) const {
	if (mCount <= index) {
		throw std::out_of_range{"Index out of range on Redis array reply"};
	}
	return tryElementFrom(mElements[index]);
}
Array::Element Array::Iterator::operator*() {
	return tryElementFrom(*ptr);
}

std::ostream& operator<<(std::ostream& stream, const Error& error) {
	return stream << "redis::Error('" << static_cast<const std::string_view&>(error) << "')";
}
std::ostream& operator<<(std::ostream& stream, const Status& status) {
	return stream << "redis::Status('" << static_cast<const std::string_view&>(status) << "')";
}
std::ostream& operator<<(std::ostream& stream, const String& str) {
	return stream << '"' << static_cast<const std::string_view&>(str) << '"';
}
std::ostream& operator<<(std::ostream& stream, const Array& array) {
	stream << "redis::Array{";
	if (0 < array.size()) {
		stream << "\n";
		for (auto elem : array) {
			stream << "\t" << StreamableVariant(elem) << ",\n";
		}
	}
	return stream << "}";
}
std::ostream& operator<<(std::ostream& stream, const Disconnected&) {
	return stream << "redis::Disconnected()";
}
std::ostream& operator<<(std::ostream& stream, const Nil&) {
	return stream << "redis::Nil()";
}

ArrayOfPairs Array::pairwise() const {
	return {mElements, mCount};
}

ArrayOfPairs::ArrayOfPairs(const redisReply* const* elements, std::size_t count)
    : mElements(elements), mCount(count / 2) {
	if (count % 2 != 0) {
		throw std::logic_error{"Cannot view uneven Redis array as array of pairs"};
	}
}

std::pair<Array::Element, Array::Element> ArrayOfPairs::operator[](std::size_t index) const {
	if (mCount <= index) {
		throw std::out_of_range{"Index out of range on Redis tuples array reply"};
	}
	index *= 2;
	return {tryElementFrom(mElements[index]), tryElementFrom(mElements[index + 1])};
}
std::pair<Array::Element, Array::Element> ArrayOfPairs::Iterator::operator*() {
	return {tryElementFrom(*ptr), tryElementFrom(*(ptr + 1))};
}

} // namespace flexisip::redis::reply
