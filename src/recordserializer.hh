/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include <string>

#include "registrar/record.hh"

namespace flexisip {

class RecordSerializer {
	static RecordSerializer* sInstance;

public:
	virtual ~RecordSerializer() {
	}
	static RecordSerializer* get();
	static RecordSerializer* create(const std::string& name);
	virtual bool parse(const char* str, int len, Record* r) = 0;
	bool parse(const std::string& str, Record* r) {
		return parse(str.c_str(), str.length(), r);
	}
	virtual bool serialize(Record* r, std::string& serialized, bool log) = 0;
	bool serialize(Record* r, std::string& serialized) {
		return serialize(r, serialized, false);
	}
};

class RecordSerializerC : public RecordSerializer {
public:
	virtual ~RecordSerializerC() {
	}
	virtual bool parse(const char* str, int len, Record* r);
	virtual bool serialize(Record* r, std::string& serialized, bool log);
};

class RecordSerializerJson : public RecordSerializer {
public:
	virtual bool parse(const char* str, int len, Record* r);
	virtual bool serialize(Record* r, std::string& serialized, bool log);
};

#ifdef ENABLE_PROTOBUF
class RecordSerializerPb : public RecordSerializer {
public:
	RecordSerializerPb();
	virtual bool parse(const char* str, int len, Record* r);
	virtual bool serialize(Record* r, std::string& serialized, bool log);
};
#endif

#ifdef ENABLE_MSGPACK
class RecordSerializerMsgPack : public RecordSerializer {
public:
	RecordSerializerMsgPack();
	virtual bool parse(const char* str, int len, Record* r);
	virtual bool serialize(Record* r, std::string& serialized, bool log);
};
#endif

} // namespace flexisip