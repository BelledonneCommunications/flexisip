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

#include <algorithm>
#include <functional>
#include <list>
#include <memory>

namespace flexisip {

/**
 * Base class that adds the ability to send notifications to a list
 * of Observer objects.
 * @param ObserverInterfaceT Class name of the interface which is implemented
 * by the Observer objects.
 */
template <typename ObserverInterfaceT>
class Observable {
public:
	/**
	 * Add an observer.
	 * Do nothing if the observer has already been added earlier.
	 */
	void addObserver(const std::shared_ptr<ObserverInterfaceT>& aObserver) noexcept {
		if (find(aObserver) == mObservers.end()) {
			mObservers.emplace_back(aObserver);
		}
	}
	/**
	 * Remove an observer.
	 * Do nothing if the observer hasn't been added before.
	 */
	void removeObserver(const std::shared_ptr<ObserverInterfaceT>& aObserver) noexcept {
		auto it = find(aObserver);
		if (it != mObservers.end()) {
			mObservers.erase(it);
		}
	}

protected:
	/**
	 * Send a notification to each observer.
	 * This method is to be called by each notify method of the derived class by
	 * giving a lambda that calls the according event method of the observer
	 * interface.
	 * @param aNotifyFn The lambda.
	 */
	void notify(const std::function<void(ObserverInterfaceT&)>& aNotifyFn) noexcept {
		for (auto it = mObservers.begin(); it != mObservers.end();) {
			auto observer = it->lock();
			if (observer == nullptr) {
				it = mObservers.erase(it);
				continue;
			}
			aNotifyFn(*observer);
			++it;
		}
	}

private:
	// Private methods
	/**
	 * Allow to clean the stale observers while searching for a
	 * specific observer.
	 * @param aObserver The observer to find.
	 * @return An iterator on an element of the Observer list. Returns
	 * the end iterator if the observer couldn't be found.
	 */
	auto find(const std::shared_ptr<ObserverInterfaceT>& aObserver) noexcept {
		for (auto it = mObservers.begin(); it != mObservers.end();) {
			auto observer = it->lock();
			if (observer == nullptr) {
				it = mObservers.erase(it);
				continue;
			}
			if (observer == aObserver) {
				return it;
			}
			++it;
		}
		return mObservers.end();
	}

	// Private attributes
	std::list<std::weak_ptr<ObserverInterfaceT>> mObservers{};
};

} // namespace flexisip