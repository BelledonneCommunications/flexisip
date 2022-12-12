/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <flexisip/logmanager.hh>

#include "recordserializer.hh"

using namespace std;

namespace flexisip {

RecordSerializer* RecordSerializer::create(const string& name) {
	if (name == "c") {
		return new RecordSerializerC();
	} else if (name == "json") {
		return new RecordSerializerJson();
	}
#if ENABLE_PROTOBUF
	else if (name == "protobuf") {
		return new RecordSerializerPb();
	}
#endif
#if ENABLE_MSGPACK
	else if (name == "msgpack") {
		return new RecordSerializerMsgPack();
	}
#endif
	else {
		return nullptr;
	}
}

RecordSerializer* RecordSerializer::sInstance = nullptr;

RecordSerializer* RecordSerializer::get() {
	if (!sInstance) {
		string name = "protobuf";
		sInstance = create(name);
		if (!sInstance) {
			LOGF("Unsupported record serializer: '%s'", name.c_str());
		}
	}
	return sInstance;
}

} // namespace flexisip
