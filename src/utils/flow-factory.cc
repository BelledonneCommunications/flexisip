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

#include "flow-factory.hh"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <random>

#include <bctoolbox/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <flexisip/logmanager.hh>

using namespace std;
namespace fs = filesystem;

namespace flexisip {

FlowFactory::Helper::Helper(const std::filesystem::path& hashKeyFilePath) {
	if (fs::exists(hashKeyFilePath)) {
		SLOGD << "FlowFactory::Helper: found hash key in " << hashKeyFilePath;
		ifstream file;
		file.open(hashKeyFilePath.c_str(), ios_base::in);
		if (!file.good()) {
			file.close();
			throw runtime_error("failed to open file " + hashKeyFilePath.string());
		}
		file.read(reinterpret_cast<char*>(mHashKey.data()), mHashKey.size());
		if (file.fail()) {
			file.close();
			throw runtime_error("an error has occurred while reading hash key file: " + hashKeyFilePath.string());
		}
		file.close();
		return;
	}

	SLOGD << "FlowFactory::Helper: no hash key file found, creating one...";

	const auto directory = hashKeyFilePath.parent_path();
	if (!fs::exists(directory)) {
		error_code error;
		if (!fs::create_directories(directory, error)) {
			throw runtime_error("an error has occurred while creating output directory(ies): " + error.message());
		}
	}

	random_device device;
	mt19937 generator(device());
	uniform_int_distribution<uint8_t> distribution(0, 255);

	for (auto& index : mHashKey) {
		index = distribution(generator);
	}

	ofstream file;
	file.open(hashKeyFilePath.c_str(), ios_base::out);
	if (!file.good()) {
		file.close();
		throw runtime_error("failed to create file " + hashKeyFilePath.string());
	}
	file.write(reinterpret_cast<char*>(mHashKey.data()), mHashKey.size());
	if (file.fail()) {
		file.close();
		throw runtime_error("an error has occurred while writing hash key in file: " + hashKeyFilePath.string());
	}
	file.close();
	SLOGD << "FlowFactory::Helper: successfully created hash key in " << hashKeyFilePath;
}

/*
 * Decode the provided flow-token and return decoded flow data and HMAC.
 */
std::pair<FlowData, Flow::HMAC> FlowFactory::Helper::decode(const Flow::Token& token) {
	auto tokenSize = (token.size() / 4) * 3 - count(token.begin(), token.end(), '=');
	Flow::RawToken rawToken(tokenSize);

	const auto* data = reinterpret_cast<const uint8_t*>(token.data());
	const auto error = bctbx_base64_decode(rawToken.data(), &tokenSize, data, token.size());

	if (error == BCTBX_ERROR_OUTPUT_BUFFER_TOO_SMALL) {
		throw runtime_error(
		    "FlowFactory::Helper::decode: an error has occurred while decoding flow-token, output buffer is too small");
	}
	if (error == BCTBX_ERROR_INVALID_BASE64_INPUT) {
		throw runtime_error("FlowFactory::Helper::decode: an error has occurred while decoding flow-token, base64 "
		                    "input data is invalid");
	}

	FlowData flowData{readSocketAddressFromRawToken(rawToken, FlowData::Address::local),
	                  readSocketAddressFromRawToken(rawToken, FlowData::Address::remote),
	                  static_cast<FlowData::Transport::Protocol>(rawToken[kHMACSize])};

	return {flowData, {rawToken.data(), rawToken.data() + kHMACSize}};
}

/*
 * Read a socket address from a decoded flow-token.
 */
std::shared_ptr<SocketAddress> FlowFactory::Helper::readSocketAddressFromRawToken(const Flow::RawToken& token,
                                                                                  FlowData::Address address) {
	su_sockaddr_t rawSocketAddress;
	const auto hmacAndTransportOffset = kHMACSize + 1;

	if (token.size() == kFlowTokenSizeIPv4) {
		auto* hostPtr = reinterpret_cast<uint8_t*>(&rawSocketAddress.su_sin.sin_addr);
		auto* portPtr = reinterpret_cast<uint8_t*>(&rawSocketAddress.su_sin.sin_port);
		rawSocketAddress.su_sa.sa_family = AF_INET;

		const auto offset = (address == FlowData::Address::local) ? 0 : sizeof(in_port_t) + sizeof(in_addr);

		const auto* dataPtr = token.data() + hmacAndTransportOffset + offset;
		memcpy(hostPtr, dataPtr, sizeof(in_addr));
		memcpy(portPtr, dataPtr + sizeof(in_addr), sizeof(in_port_t));

	} else if (token.size() == kFlowTokenSizeIPv6) {
		auto* portPtr = reinterpret_cast<uint8_t*>(&rawSocketAddress.su_sin6.sin6_port);
		auto* hostPtr = reinterpret_cast<uint8_t*>(&rawSocketAddress.su_sin6.sin6_addr);
		rawSocketAddress.su_sa.sa_family = AF_INET6;

		const auto offset = (address == FlowData::Address::local) ? 0 : sizeof(in_port_t) + sizeof(in6_addr);

		const auto* dataPtr = token.data() + hmacAndTransportOffset + offset;
		memcpy(hostPtr, dataPtr, sizeof(in6_addr));
		memcpy(portPtr, dataPtr + sizeof(in6_addr), sizeof(in_port_t));

	} else {
		throw runtime_error("FlowFactory::Helper::readSocketAddressFromRawToken: unknown token size " +
		                    to_string(token.size()));
	}

	return SocketAddress::make(&rawSocketAddress);
}

/*
 * Compute HMAC of provided raw flow data.
 */
Flow::HMAC FlowFactory::Helper::hash(const FlowData::Raw& rawData) const {
	unsigned char mdValue[EVP_MAX_MD_SIZE];
	const auto* md = EVP_get_digestbyname("SHA1");

	if (!HMAC(md, mHashKey.data(), mHashKey.size(), rawData.data(), rawData.size(), mdValue, nullptr)) {
		throw runtime_error("FlowFactory::Helper::computeHMAC: an error has occurred while computing HMAC");
	}

	return {mdValue, mdValue + kHMACSize};
}

/*
 * Encode raw flow data into a flow-token.
 */
Flow::Token FlowFactory::Helper::encode(const FlowData::Raw& rawData) const {
	const auto tokenSize = kHMACSize + rawData.size();
	auto encodedTokenSize = static_cast<size_t>(ceil(((4 * tokenSize) + 2) / 3) + 5);

	Flow::RawToken token(tokenSize);
	memcpy(token.data(), hash(rawData).c_str(), kHMACSize);
	memcpy(token.data() + kHMACSize, rawData.data(), rawData.size());

	Flow::RawToken encodedToken(encodedTokenSize);

	if (bctbx_base64_encode(encodedToken.data(), &encodedTokenSize, token.data(), token.size()) != 0) {
		throw runtime_error("FlowFactory::Helper::encode: error while encoding in base64, output buffer is too small");
	}

	return {encodedToken.data(), encodedToken.data() + encodedTokenSize};
}

const FlowFactory::Helper::HashKey& FlowFactory::Helper::getHashKey() const {
	return mHashKey;
}

/*
 * Create a flow from an encoded flow-token.
 */
Flow FlowFactory::create(const Flow::Token& token) const {
	auto [data, hmac] = Helper::decode(token);
	return {std::move(data), token, mHelper.hash(data.raw()) != hmac};
}

/*
 * Create a flow from "raw" information.
 */
Flow FlowFactory::create(const std::shared_ptr<SocketAddress>& local,
                         const std::shared_ptr<SocketAddress>& remote,
                         std::string_view transportProtocolName) const {
	if (local == nullptr) {
		throw runtime_error("local address data pointer is empty");
	}
	if (remote == nullptr) {
		throw runtime_error("remote address data pointer is empty");
	}
	if (local->getAddressFamily() != remote->getAddressFamily()) {
		throw runtime_error("local and remote socket ip address families do not match (local = " + local->str() +
		                    ", remote = " + remote->str() + ")");
	}

	FlowData data{local, remote, FlowData::Transport::enm(transportProtocolName)};
	return {std::move(data), mHelper.encode(data.raw()), false};
}

FlowFactory::FlowFactory(Helper& factoryUtils) : mHelper(factoryUtils) {
}

FlowFactory::FlowFactory(const std::filesystem::path& hashKeyFilePath) : mHelper(hashKeyFilePath) {
}

/*
 * Check whether the provided token is a valid flow-token.
 */
bool FlowFactory::tokenIsValid(const Flow::Token& token) const {
	if (token.size() != Helper::kEncodedFlowTokenSizeIPv4 and token.size() != Helper::kEncodedFlowTokenSizeIPv6) {
		SLOGD << "FlowFactory::tokenIsValid: invalid flow-token size " << token.size();
		return false;
	}

	try {
		const auto flow = create(token);
		if (flow.mData.mTransportProtocol == FlowData::Transport::Protocol::unknown) {
			SLOGD << "FlowFactory::tokenIsValid: invalid transport protocol (unknown)";
			return false;
		}
		if (flow.isFalsified()) {
			SLOGD << "FlowFactory::tokenIsValid: invalid HMAC (token may have been tampered with)";
			return false;
		}
	} catch (const exception& error) {
		SLOGD << "FlowFactory::tokenIsValid: an error has occurred while verifying token (" << error.what() << ")";
		return false;
	}

	return true;
}

} // namespace flexisip