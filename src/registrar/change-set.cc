/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "change-set.hh"

#include "extended-contact.hh"

using namespace std;

namespace flexisip {

ostream& operator<<(ostream& stream, const ChangeSet& changeSet) {
	time_t now = getCurrentTime();
	time_t offset = getTimeOffset(now);
	stream << "ChangeSet {\n";
	stream << "mDelete (" << changeSet.mDelete.size() << "): [";
	for (const auto& contact : changeSet.mDelete) {
		stream << "\n\t";
		contact->print(stream, now, offset);
	}
	stream << "\n], mUpsert (" << changeSet.mUpsert.size() << "): [";
	for (const auto& contact : changeSet.mUpsert) {
		stream << "\n\t";
		contact->print(stream, now, offset);
	}
	return stream << "\n]}";
}

} // namespace flexisip
