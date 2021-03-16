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

namespace flexisip {

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

	void connect() noexcept;
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

	int read(void* data, int dlen) noexcept;

	int write(const std::vector<char>& data) noexcept {
		return write(data.data(), data.size());
	}
	int write(const void* data, int dlen) noexcept;

	bool waitForData(int timeout) const;
	bool hasData() const {
		return waitForData(0);
	}

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

	BIOUniquePtr mBio{nullptr};
	SSLCtxUniquePtr mCtx{nullptr};
	std::string mHost{}, mPort{};
	bool mMustBeHttp2 = false;
	std::chrono::milliseconds mTimeout{1000};
};

} // namespace flexisip
