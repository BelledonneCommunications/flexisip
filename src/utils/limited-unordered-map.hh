/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#include <algorithm>
#include <optional>
#include <queue>
#include <unordered_map>

/**
 * @class LimitedUnorderedMap
 * @brief A container that combines an unordered map with a limited size and a queue to maintain insertion order.
 *
 * This class provides an unordered map with a maximum size limit. When the size exceeds the limit,
 * the oldest element (based on insertion order) is removed. It uses a deque to maintain the order of keys
 * and ensures efficient operations.
 *
 * @tparam Key   The type of the keys in the map.
 * @tparam Value The type of the values in the map.
 */
template <typename Key, typename Value>
class LimitedUnorderedMap {
public:
	using MapType = std::unordered_map<Key, Value>;
	using QueueType = std::deque<Key>;
	using NodeType = typename MapType::node_type;

	/**
	 * @brief Constructor to initialize the map with a maximum size.
	 *
	 * @param maxSize The maximum number of elements that the map can hold.
	 */
	explicit LimitedUnorderedMap(const size_t maxSize) : mMaxSize(maxSize) {
	}
	~LimitedUnorderedMap() = default;

	auto erase(const Key& key) {
		if (auto erasedNb = mMap.erase(key); erasedNb == 0) return erasedNb;

		if (auto itQ = std::find(mQueue.begin(), mQueue.end(), key); itQ != mQueue.end()) {
			mQueue.erase(itQ);
		}

		return 1;
	}

	template <typename Iterator>
	auto erase(Iterator& it) {
		auto key = it->first;
		auto result = mMap.erase(it);

		if (auto itQ = std::find(mQueue.begin(), mQueue.end(), key); itQ != mQueue.end()) {
			mQueue.erase(itQ);
		}

		return result;
	}

	/**
	 * @brief Tries to emplace an element into the map.
	 *
	 * If the element is successfully emplaced and the size exceeds the maximum size,
	 * the oldest element is removed.
	 */
	template <typename... Args>
	auto try_emplace(const Key& key, Args&&... args) {
		auto result = mMap.try_emplace(key, std::forward<Args>(args)...);
		if (!result.second) return result;

		mQueue.push_back(key);
		if (mQueue.size() > mMaxSize) {
			const auto& keyToDelete = mQueue.front();
			mMap.erase(keyToDelete);
			mQueue.pop_front();
		}

		return result;
	}

	/**
	 * @brief Merges another LimitedUnorderedMap into this one.
	 *
	 * Elements are alternately added, to create a new map, from the other map and this map until the maximum size is
	 * reached.
	 *
	 * eg. if maxSize = 3, {1,2,3}.merge({11,12,13}) --> {1,11,2}
	 */
	void merge(LimitedUnorderedMap& otherMap) {
		MapType newMap{};
		QueueType newQueue{};

		auto frontNode = extractFirstNode();
		auto otherFrontNode = otherMap.extractFirstNode();
		while (newQueue.size() < mMaxSize && (frontNode || otherFrontNode)) {
			if (frontNode.has_value()) {
				newQueue.push_back(frontNode->key());
				newMap.insert(std::move(*frontNode));
				frontNode = extractFirstNode();
			}
			if (otherFrontNode.has_value() && newQueue.size() < mMaxSize) {
				newQueue.push_back(otherFrontNode->key());
				newMap.insert(std::move(*otherFrontNode));
				otherFrontNode = otherMap.extractFirstNode();
			}
		}

		mQueue = std::move(newQueue);
		mMap = std::move(newMap);
	}

	auto find(const Key& key) {
		return mMap.find(key);
	}
	auto find(const Key& key) const {
		return mMap.find(key);
	}
	auto begin() {
		return mMap.begin();
	}
	auto end() {
		return mMap.end();
	}
	auto begin() const {
		return mMap.begin();
	}
	auto end() const {
		return mMap.end();
	}
	auto size() const {
		return mMap.size();
	}
	auto empty() const {
		return mMap.empty();
	}

private:
	std::optional<NodeType> extractFirstNode() {
		if (!mQueue.empty()) {
			auto keyToExtract = mQueue.front();
			mQueue.pop_front();
			if (auto extractedNode = mMap.extract(keyToExtract); extractedNode) {
				return std::make_optional(std::move(extractedNode));
			}
		}
		return std::nullopt;
	}

	MapType mMap{};
	QueueType mQueue{};
	size_t mMaxSize;
};