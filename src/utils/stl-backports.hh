/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <memory>

namespace flexisip {
// Backports of the C++ Standard Library
namespace stl_backports {

template <typename Signature>
class move_only_function;

// https://en.cppreference.com/w/cpp/utility/functional/move_only_function
// Allows moving data in and out of a function, which is required for e.g. std::unique_ptr,
// but impossible with a std::function
template <typename TReturn, typename... Args>
class move_only_function<TReturn(Args...)> {
public:
	move_only_function() noexcept = default;
	move_only_function(move_only_function&& other) = default;
	template <typename TFunction>
	move_only_function(TFunction&& function) : mPtr(std::make_unique<WrappedFunction<TFunction>>(std::move(function))) {
	}

	// "Unlike std::function, invoking an empty std::move_only_function results in undefined behavior."
	TReturn operator()(Args&&... args) {
		return (*mPtr)(std::forward<Args>(args)...);
	}

	operator bool() {
		return mPtr.operator bool();
	}

private:
	class TypeErasedFunction {
	public:
		virtual ~TypeErasedFunction() = default;

		virtual TReturn operator()(Args&&...) = 0;
	};

	template <typename TFunction>
	class WrappedFunction : public TypeErasedFunction {
	public:
		WrappedFunction(TFunction&& function) : mWrapped(std::move(function)) {
		}

		TReturn operator()(Args&&... args) {
			return mWrapped(std::forward<Args>(args)...);
		}

	private:
		TFunction mWrapped;
	};

	std::unique_ptr<TypeErasedFunction> mPtr{};
};

} // namespace stl_backports
} // namespace flexisip
