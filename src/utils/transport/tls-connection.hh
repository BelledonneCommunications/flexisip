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

#include <chrono>
#include <condition_variable>
#include <cstring>
#include <stdexcept>
#include <thread>
#include <vector>

#include <openssl/ssl.h>
#include <sofia-sip/su_wait.h>

#include <flexisip/logmanager.hh>

#include "../thread/must-finish-thread.hh"

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

	class CreationError : public std::runtime_error {
	public:
		CreationError() : std::runtime_error("Error during TlsConnection creation") {
		}
	};

	TlsConnection(const std::string& host, const std::string& port, bool mustBeHttp2 = false);
	TlsConnection(const std::string& host,
	              const std::string& port,
	              const std::string& trustStorePath,
	              const std::string& certPath,
	              bool mustBeHttp2 = false);
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
	void connectAsync(su_root_t& root, const std::function<void()>& onConnectCb) noexcept;

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
	/**
	 * @brief Return the local port which has been attributed while connection.
	 * @return The local port or 0 if isConnected() == false.
	 * @throw std::system_error if the socket name couldn't be fetched.
	 */
	std::uint16_t getLocalPort() const;

	int read(std::vector<char>& data, int readSize) noexcept {
		data.resize(readSize);
		auto nRead = read(data.data(), readSize);
		data.resize(std::max(0, nRead));
		return nRead;
	}
	int read(void* data, int dlen) noexcept;

	template <typename ContainerT>
	int readAll(ContainerT& result, std::chrono::milliseconds timeout = std::chrono::milliseconds{2000}) noexcept {
		auto now = std::chrono::steady_clock::now();
		auto nowPlusTimeout = now + timeout;
		char readBuffer[1024];
		int nbRead = 0;
		result.clear();

		while (nbRead == 0 && now < nowPlusTimeout) {
			try {
				if (!waitForData(std::chrono::duration_cast<std::chrono::milliseconds>(nowPlusTimeout - now))) {
					return 0;
				}
			} catch (const std::runtime_error& e) {
				return -1;
			}

			// Read can return 0 if only TLS data were present.
			nbRead = this->read(readBuffer, sizeof(readBuffer));

			if (nbRead < 0) {
				return nbRead;
			} else if (nbRead == 0) {
				now = std::chrono::steady_clock::now();
			}
		}
		result.insert(result.end(), readBuffer, readBuffer + nbRead);

		// read until the socket is empty or an error occurs.
		while ((nbRead = this->read(readBuffer, sizeof(readBuffer))) > 0) {
			result.insert(result.end(), readBuffer, readBuffer + nbRead);
		}
		if (nbRead < 0) {
			return nbRead;
		}

		return result.size();
	}

	template <typename ContinuousContainer>
	int write(const ContinuousContainer& data) noexcept {
		return write(data.data(), data.size());
	}
	int write(const char* cStr) noexcept {
		return write(cStr, std::strlen(cStr));
	}
	int write(const void* data, int dlen) noexcept;

	bool waitForData(std::chrono::milliseconds timeout) const;
	bool hasData() const {
		return waitForData(std::chrono::milliseconds{0});
	}

	void setTimeout(const std::chrono::milliseconds& timeout) {
		TlsConnection::mTimeout = timeout;
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
	static SSLCtxUniquePtr makeDefaultCtx();
	static int getFd(BIO& bio);

	static void doConnectCb(su_root_magic_t* rm, su_msg_r msg, void* u);
	void doConnectAsync(su_root_t& root, const std::function<void()>& onConnectCb);

	BIOUniquePtr mBio{nullptr};
	SSLCtxUniquePtr mCtx{nullptr};
	std::string mHost{}, mPort{};
	bool mMustBeHttp2 = false;
	std::chrono::milliseconds mTimeout{20000};
	MustFinishThread mThread;
};

} // namespace flexisip
