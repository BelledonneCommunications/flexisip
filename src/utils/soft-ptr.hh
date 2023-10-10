/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <functional>
#include <memory>
#include <variant>

#include "utils/variant-utils.hh"

namespace flexisip {

// A general-purpose smart-pointer to an interface.
// It can either be owning (constructed from a shared_ptr or unique_ptr), or non-owning (constructed from a weak_ptr or
// a reference). It exposes an API similar to that of a weak_ptr, in that you must acquire a temporary Lock on the
// pointee to access its methods.
//
// It gives the user maximum freedom over their memory management strategy, as they may:
//  - Pass a build-and-forget instance of a listener that will be held for as long as needs be (by passing a unique_ptr
//  or shared_ptr)
//  - Pass an auto-disabling listener that can be safely freed when it is no longer needed (by passing a weak_ptr)
//  - Pass a ref to an object which is known at design time to outlive the borrow (e.g. static variable, or class
//    composed by the ref) without requiring it to inherit enable_shared_from_this (by passing a raw reference)
template <typename Interface>
class SoftPtr {
public:
	// A temporary strong reference to the listener, suitable to call its methods
	class Lock {
	public:
		friend class SoftPtr;

		// Prevent dangling references
		Lock(const Lock&) = delete;
		Lock(Lock&&) = delete;

		Interface* operator->() {
			return Match<decltype(mStrongHandle)&>(mStrongHandle)
			    .against([](std::shared_ptr<Interface>& strongPtr) { return strongPtr.operator->(); },
			             [](Interface* rawPtr) { return rawPtr; });
		}

		// Can the Lock be dereferenced?
		operator bool() const {
			return std::visit([](const auto& handle) { return bool(handle); }, mStrongHandle);
		}

	private:
		Lock(std::shared_ptr<Interface>&& shared) : mStrongHandle(std::move(shared)) {
		}
		Lock(Interface* unsafe) : mStrongHandle(unsafe) {
		}

		std::variant<std::shared_ptr<Interface>, Interface*> mStrongHandle;
	};

	SoftPtr() : mHandle(std::unique_ptr<Interface>{nullptr}) {
	}
	SoftPtr(std::weak_ptr<Interface>&& weak) : mHandle(std::move(weak)) {
	}
	SoftPtr(std::unique_ptr<Interface>&& unique) : mHandle(std::move(unique)) {
	}
	// Explicit to help debug reference cycles
	explicit SoftPtr(std::shared_ptr<Interface>&& strong) : mHandle(std::move(strong)) {
	}
	// Static method with explicit name to nudge users into ensuring they know what they are doing and have
	// double-checked the lifetimes of their objets
	// SAFETY: The returned Listener instance MUST NOT outlive the object referenced by `ref`
	static SoftPtr fromObjectLivingLongEnough(Interface& ref) {
		return SoftPtr(ref);
	}

	// Acquiring a lock may fail (the listener may have been freed), so you must check the returned Lock before
	// accessing it
	Lock lock() {
		return Match<decltype(mHandle)&>(mHandle).against(
		    [](std::unique_ptr<Interface>& unique) -> Lock { return unique.get(); },
		    [](std::reference_wrapper<Interface> ref) -> Lock { return std::addressof(ref.get()); },
		    [](std::shared_ptr<Interface> strong) -> Lock { return strong; },
		    [](std::weak_ptr<Interface> weak) -> Lock { return weak.lock(); });
	}

private:
	explicit SoftPtr(Interface& raw) : mHandle(raw) {
	}
	std::variant<std::unique_ptr<Interface>,
	             std::weak_ptr<Interface>,
	             std::shared_ptr<Interface>,
	             std::reference_wrapper<Interface>>
	    mHandle;
};

} // namespace flexisip
