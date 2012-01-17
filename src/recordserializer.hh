/*
	Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2012  Belledonne Communications SARL.
    Author: Guillaume Beraudo

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef recordserializer_hh
#define recordserializer_hh

#include "registrardb.hh"


class RecordSerializer {
	static RecordSerializer *sInstance;
public:
	static RecordSerializer *get();
	virtual bool parse(const char *str, int len, Record *r)=0;
	virtual bool serialize(Record *r, std::string &serialized)=0;
};

class RecordSerializerC : public RecordSerializer {
public:
	RecordSerializerC(){};
	~RecordSerializerC(){};
	virtual bool parse(const char *str, int len, Record *r);
	virtual bool serialize(Record *r, std::string &serialized);
};

class RecordSerializerJson : public RecordSerializer {
public:
	RecordSerializerJson(){};
	~RecordSerializerJson(){};
	virtual bool parse(const char *str, int len, Record *r);
	virtual bool serialize(Record *r, std::string &serialized);
};

#ifdef ENABLE_PROTOBUF
class RecordSerializerPb : public RecordSerializer {
public:
	RecordSerializerPb();
	~RecordSerializerPb(){};
	virtual bool parse(const char *str, int len, Record *r);
	virtual bool serialize(Record *r, std::string &serialized);
};
#endif

#endif
