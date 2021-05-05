/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2010-2021  Belledonne Communications SARL, All rights reserved.

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

#pragma once

#include <chrono>
#include <condition_variable>
#include <vector>

#include <openssl/ssl.h>
#include <sofia-sip/su_wait.h>

namespace flexisip {

/**
 * A complete c++ implementation of a TLS connection over the OpenSSL library.
 * Can be used to create, configure, read and write with a TLS connection.
 */
class TlsConnection {
public:
	struct SSLCtxDeleter {
		void operator()(SSL_CTX* ssl) noexcept {
			SSL_CTX_free(ssl);
		}
	};
	using SSLCtxUniquePtr = std::unique_ptr<SSL_CTX, SSLCtxDeleter>;

	TlsConnection(const std::string& host, const std::string& port, bool mustBeHttp2 = false) noexcept;
	TlsConnection(const std::string& host, const std::string& port, const std::string& trustStorePath,
	              const std::string& certPath, bool mustBeHttp2 = false);
	TlsConnection(const TlsConnection&) = delete;
	TlsConnection(TlsConnection&&) = delete;

	const std::string& getHost() const noexcept {
		return mHost;
	}
	const std::string& getPort() const noexcept {
		return mPort;
	}

	/**
	 * Method used to establish the connection between you and the server. This is a bocking connection. The connection
	 * is established with all furthers I/O set as non-blocking.
	 */
	void connect() noexcept;

	/**
	 * Method used to establish the connection between you and the server. This method run asynchronously and add a
	 * callback to the sofia-sip loop on connection success/error. The connection is established with all furthers I/O
	 * set as non-blocking.
	 *
	 * @param root sofia-sip loop root object
	 * @param onConnectCb callback to call after connection success/error
	 */
	void connectAsync(su_root_t& root, std::function<void()> onConnectCb) noexcept;

	void disconnect() noexcept {
		mBio.reset();
	}
	void resetConnection() noexcept;

	bool isConnected() const noexcept {
		return mBio != nullptr;
	}
	bool isSecured() const noexcept {
		return mCtx != nullptr;
	}

	BIO* getBIO() const noexcept {
		return mBio.get();
	}
	int getFd() const noexcept;

	int read(void* data, int dlen, std::chrono::milliseconds timeout = std::chrono::milliseconds{2000}) noexcept;

	template <typename ContainerT>
	int readAll(ContainerT& result, std::chrono::milliseconds timeout = std::chrono::milliseconds{2000}) noexcept {
		char readBuffer[1024];
		result.clear();

		// first read with timeout
		auto nbRead = this->read(readBuffer, sizeof(readBuffer), timeout);
		if (nbRead < 0) {
			return nbRead;
		}
		result.insert(result.end(), readBuffer, readBuffer + nbRead);

		// read until the socket is empty or an error occurs.
		while ((nbRead = this->read(readBuffer, sizeof(readBuffer), std::chrono::milliseconds{0})) > 0) {
			result.insert(result.end(), readBuffer, readBuffer + nbRead);
		}
		if (nbRead < 0) {
			return nbRead;
		}

		return result.size();
	}

	int write(const std::vector<char>& data) noexcept {
		return write(data.data(), data.size());
	}
	int write(const void* data, int dlen) noexcept;

	bool waitForData(std::chrono::milliseconds timeout) const;
	bool hasData() const {
		return waitForData(std::chrono::milliseconds{0});
	}

	void enableInsecureTestMode();

private:
	struct BIODeleter {
		void operator()(BIO* bio) {
			BIO_free_all(bio);
		}
	};
	using BIOUniquePtr = std::unique_ptr<BIO, BIODeleter>;

	static void handleBioError(const std::string& msg, int status);
	static int handleVerifyCallback(X509_STORE_CTX* ctx, void* ud);
	static bool isCertExpired(const std::string& certPath) noexcept;
	static int ASN1_TIME_toString(const ASN1_TIME* time, char* buffer, uint32_t buff_length);
	static SSL_CTX* getDefaultCtx();
	static int getFd(BIO& bio);

	static void doConnectCb(su_root_magic_t* rm, su_msg_r msg, void* u);
	void doConnectAsync(su_root_t& root, std::function<void()> onConnectCb);

	BIOUniquePtr mBio{nullptr};
	SSLCtxUniquePtr mCtx{nullptr};
	std::string mHost{}, mPort{};
	bool mMustBeHttp2 = false;
	std::chrono::milliseconds mTimeout{5000};
};

} // namespace flexisip
