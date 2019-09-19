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

#include <cstring>
#include <stdexcept>

#include <bctoolbox/crypto.h>

#include "digest.hh"

using namespace std;

namespace flexisip {

template <>
std::vector<uint8_t> Digest::compute<std::vector<uint8_t>>(const void *data, size_t size) {
	return computeBinaryDigest(data, size);
}

template <>
std::string Digest::compute<std::string>(const void *data, size_t size) {
	return computePrintableDigest(data, size);
}

Digest *Digest::create(const std::string &algo) {
	if (strcasecmp(algo.c_str(), "md5") == 0) return new Md5();
	else if (strcasecmp(algo.c_str(), "sha256") == 0 || strcasecmp(algo.c_str(), "sha-256") == 0) return new Sha256();
	else throw invalid_argument("unknown digest implementation: '" + algo + "'");
}

std::string Digest::toHexString(const std::vector<uint8_t> &data) {
	char formatedByte[3];
	string res;

	res.reserve(data.size() * 2);
	for (const uint8_t &byte : data) {
		snprintf(formatedByte, sizeof(formatedByte), "%02hhx", byte);
		res += formatedByte;
	}
	return res;
}

std::vector<uint8_t> Md5::computeBinaryDigest(const void *data, size_t size) {
	vector<uint8_t> res(16);
	bctbx_md5(static_cast<const uint8_t *>(data), size, res.data());
	return res;
}

const std::string Md5::sName = "MD5";


std::vector<uint8_t> Sha256::computeBinaryDigest(const void *data, size_t size) {
	vector<uint8_t> hash(32);
	bctbx_sha256(static_cast<const uint8_t *>(data), size, hash.size(), hash.data());
	return hash;
}

const std::string Sha256::sName = "SHA256";

}
