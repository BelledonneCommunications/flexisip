/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <list>
#include <memory>

namespace flexisip {

struct ExtendedContact;

class ChangeSet {
public:
	std::list<std::shared_ptr<ExtendedContact>> mDelete{};
	std::list<std::shared_ptr<ExtendedContact>> mUpsert{};

	ChangeSet(const ChangeSet& other) = delete;
	ChangeSet& operator=(const ChangeSet& other) = delete;

	ChangeSet(ChangeSet&& other) = default;
	ChangeSet& operator=(ChangeSet&& other) = default;
	ChangeSet& operator+=(ChangeSet&& other) {
		mDelete.merge(other.mDelete);
		mUpsert.merge(other.mUpsert);
		return *this;
	}
};

} // namespace flexisip
