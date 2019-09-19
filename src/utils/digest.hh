/*
 * Flexisip, a flexible SIP proxy server with media capabilities.
 * Copyright (C) 2011  Belledonne Communications SARL, All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace flexisip {

class Digest {
public:
	virtual ~Digest() = default;

	virtual const std::string &name() const = 0;

	template <class ResultT, class DataT>
	ResultT compute(const DataT &data) {
		return compute<ResultT>(data.data(), data.size());
	}

	template <class ResultT>
	ResultT compute(const char *str) {
		return compute<ResultT>(str, strlen(str));
	}

	template <class ResultT>
	ResultT compute(const void *data, size_t size);

	static Digest *create(const std::string &algo);

private:
	virtual std::vector<uint8_t> computeBinaryDigest(const void *data, size_t size) = 0;
	std::string computePrintableDigest(const void *data, size_t size) {
		return toHexString(computeBinaryDigest(data, size));
	}

	static std::string toHexString(const std::vector<uint8_t> &data);
};

class Md5 : public Digest {
private:
	const std::string &name() const override {return sName;}
	std::vector<uint8_t> computeBinaryDigest(const void *data, size_t size) override;

	static const std::string sName;
};

class Sha256 : public Digest {
private:
	const std::string &name() const override {return sName;}
	std::vector<uint8_t> computeBinaryDigest(const void *data, size_t size) override;

	static const std::string sName;
};

}
