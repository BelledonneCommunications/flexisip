/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>

#include "flexisip/sofia-wrapper/su-root.hh"
#include "tls-connection-establishment-strategy.hh"
#include "utils/thread/must-finish-thread.hh"
#include "utils/transport/http/https-proxy-cfg.hh"

namespace flexisip {

/**
 * A complete c++ implementation of a TLS connection over the OpenSSL library.
 *
 * Instances using connectAsync() MUST be owned by a std::shared_ptr: the connection thread
 * keeps a reference on the connection during the blocking establishment, and the completion
 * posted to the main loop accesses it through a weak reference.
 */
class TlsConnection : public std::enable_shared_from_this<TlsConnection> {
public:
	class CreationError : public std::runtime_error {
	public:
		explicit CreationError(const std::string& message)
		    : std::runtime_error("failed to create TLSConnection, reason = " + message) {}
	};

	/**
	 * @brief Instantiate a new TLS connection as a shared pointer.
	 *
	 * @note This is the only way to create a TlsConnection. The class extends
	 * std::enable_shared_from_this, so instances must be owned through a std::shared_ptr.
	 *
	 * @note std::make_shared cannot be used here because the constructors are private,
	 * and make_shared requires a public constructor.
	 */
	template <typename... Args>
	static std::shared_ptr<TlsConnection> make(Args&&... args) {
		return std::shared_ptr<TlsConnection>{new TlsConnection{std::forward<Args>(args)...}};
	}

	TlsConnection(const TlsConnection&) = delete;
	TlsConnection(TlsConnection&&) = delete;
	~TlsConnection();

	const std::string& getHost() const noexcept {
		return mHost;
	}
	const std::string& getPort() const noexcept {
		return mPort;
	}

	/**
	 * @brief Establish connection with the other end.
	 *
	 * @note You can customize the connection timeout using setTimeout().
	 * @details The connection is established with all furthers I/O set as non-blocking.
	 * @warning This is a blocking operation.
	 */
	void connect() noexcept;

	/**
	 * @brief Establish connection with the other end.
	 *
	 * @note You can customize the connection timeout using setTimeout().
	 * @details This method runs asynchronously: the blocking connection establishment
	 * (DNS, TCP, TLS) runs on a dedicated thread, and the resulting connection is applied
	 * on the main loop, which then invokes `onConnectCb` whether the establishment
	 * succeeded or failed (unless the connection was destroyed in the meantime, in which
	 * case the fresh socket is discarded). The main loop is the only thread to ever touch
	 * the connected state of this object.
	 * If the connection is already established, no connection attempt is made and
	 * `onConnectCb` is still invoked on the main loop.
	 *
	 * @param root sofia-sip loop root object
	 * @param onConnectCb callback to call after connection success/error, on the main loop
	 */
	void connectAsync(sofiasip::SuRoot& root, const std::function<void()>& onConnectCb) noexcept;

	void disconnect() noexcept;

	/**
	 * Consecutively executes disconnect/connect.
	 *
	 * @warning This is a blocking operation.
	 */
	void resetConnection() noexcept;

	bool isConnected() const noexcept {
		return mBio != nullptr;
	}
	bool isSecured() const noexcept {
		return mCtx != nullptr;
	}

	int getFd() const noexcept;

	/**
	 * @brief Get the local port that has been assigned when connecting to the other end.
	 *
	 * @return The local port or 0 if isConnected() == false.
	 * @throw std::system_error if the socket name could not be fetched.
	 * @throw std::logic_error if address family is invalid.
	 */
	std::uint16_t getLocalPort() const;

	/**
	 * @brief Attempt to read data from file descriptor.
	 *
	 * @param data output buffer
	 * @param dlen number of bytes to read
	 *
	 * @warning disconnect if EOF is read or connection is closed.
	 *
	 * @return number of bytes read from file descriptor. A value of zero means "retry later": the socket may be empty
	 * or there were not enough data to form a complete TLS message.
	 */
	int read(void* data, int dlen) noexcept;
	/**
	 * @brief Attempt to read data from file descriptor.
	 *
	 * @param data output buffer
	 * @param readSize number of bytes to read
	 *
	 * @warning disconnect if EOF is read or connection is closed.
	 *
	 * @return number of bytes read from file descriptor. A value of zero means "retry later": the socket may be empty
	 * or there were not enough data to form a complete TLS message.
	 */
	int read(std::vector<char>& data, int readSize) noexcept;
	/**
	 * @brief Attempt to fetch and read data from file descriptor for a given amount of time.
	 *
	 * @param result output buffer
	 * @param timeout amount of time for an event to occur @see waitForData()
	 *
	 * @warning 1. disconnect if EOF is read or connection is closed
	 *          2. this is a blocking operation
	 *
	 * @return number of bytes read from file descriptor. A value of zero means "retry later".
	 */
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

			// Read can only return 0 if TLS data were present.
			nbRead = this->read(readBuffer, sizeof(readBuffer));

			if (nbRead < 0) {
				return nbRead;
			} else if (nbRead == 0) {
				now = std::chrono::steady_clock::now();
			}
		}
		result.insert(result.end(), readBuffer, readBuffer + nbRead);

		// Read until the socket is empty or an error occurs.
		while ((nbRead = this->read(readBuffer, sizeof(readBuffer))) > 0) {
			result.insert(result.end(), readBuffer, readBuffer + nbRead);
		}
		if (nbRead < 0) {
			return nbRead;
		}

		return result.size();
	}

	/**
	 * @brief Attempt to write data to file descriptor.
	 *
	 * @param data data buffer
	 * @param dlen number of bytes to write
	 *
	 * @return number of bytes written to file descriptor. If -1, an error occurred. If 0, BIO is null or dlen <= 0.
	 */
	int write(const void* data, int dlen) noexcept;
	/**
	 * @brief Attempt to write a string to file descriptor.
	 *
	 * @param cStr string to write
	 *
	 * @return number of bytes written to file descriptor. If -1, an error occurred. If 0, BIO is null or dlen <= 0.
	 */
	int write(const char* cStr) noexcept;
	/**
	 * @brief Attempt to write data to file descriptor.
	 *
	 * @param data STL continuous data container
	 *
	 * @return number of bytes written to file descriptor. If -1, an error occurred. If 0, BIO is null or dlen <= 0.
	 */
	template <typename ContinuousContainer>
	int write(const ContinuousContainer& data) noexcept {
		return write(data.data(), data.size());
	}

	/**
	 * Execute poll() on file descriptor for given amount of time to check if there are data to read.
	 *
	 * @param timeout amount of time for an event to occur. If strictly positive, allow given time for an event to
	 * occur. If 0, executes without blocking. If -1, blocks until an event occurs.
	 *
	 * @warning this can be a blocking operation.
	 *
	 * @return true if there are data to read from the socket.
	 */
	bool waitForData(std::chrono::milliseconds timeout);
	/**
	 * Execute poll() on file descriptor in the non-blocking mode @see waitForData().
	 *
	 * @return true if there are data to read from the socket.
	 */
	bool hasData();

	/**
	 * Set connection timeout used when connecting to the other end.
	 *
	 * @param timeout new value
	 */
	void setTimeout(const std::chrono::milliseconds& timeout) {
		mTimeout = timeout;
	}

	/**
	 * Enable specific mode for testing purposes.
	 *
	 * @warning do not use this mode in production applications.
	 */
	void enableInsecureTestMode();

private:
	/**
	 * @brief Instantiate a new TLS connection.
	 *
	 * @param host other end IP address
	 * @param port other end port
	 * @param mustBeHttp2 whether or not to force use of HTTP/2
	 * @param httpsProxyCfg configuration of the HTTPS proxy to use for tunneling, or nullopt to
	 * connect directly
	 */
	TlsConnection(const std::string& host,
	              std::string_view port,
	              bool mustBeHttp2 = false,
	              const std::optional<HttpsProxyCfg>& httpsProxyCfg = std::nullopt);
	/**
	 * Instantiate a new TLS or TCP connection.
	 *
	 * @note You can leave trustStorePath and certPath empty in order to create a simple TCP connection.
	 *
	 * @param host other end IP address
	 * @param port other end port
	 * @param trustStorePath path to the truststore (cacert file)
	 * @param certPath path to the certificate
	 * @param mustBeHttp2 whether or not to force use of HTTP/2
	 * @param httpsProxyCfg configuration of the HTTPS proxy to use for tunneling, or nullopt to
	 * connect directly
	 */
	TlsConnection(const std::string& host,
	              std::string_view port,
	              const std::string& trustStorePath,
	              const std::string& certPath,
	              bool mustBeHttp2 = false,
	              const std::optional<HttpsProxyCfg>& httpsProxyCfg = std::nullopt);

	/**
	 * Utility function to convert ASN1_TIME to a printable string in a buffer.
	 */
	static int ASN1_TIME_toString(const ASN1_TIME* time, char* buffer, uint32_t buff_length);
	static SSLCtxUniquePtr makeDefaultCtx();
	std::string loadCertificate();

	/**
	 * Result of a connection establishment: the connected BIO with its SSL, or nullopt if
	 * it failed.
	 */
	using ConnectResult = std::optional<std::pair<BIOUniquePtr, SSLUniquePtr>>;
	/**
	 * Blocking connection establishment: reloads the client certificate if any and runs the
	 * establishment strategy. Does NOT modify mBio/mSsl.
	 */
	ConnectResult establishConnection();

	static int handleVerifyCallback(X509_STORE_CTX* ctx, void* ud);

	int getFd(BIO& bio) const;

	bool isCertExpired(const std::string& certPath) noexcept;

	BIOUniquePtr mBio{nullptr};
	SSLUniquePtr mSsl{nullptr};
	SSLCtxUniquePtr mCtx{nullptr};
	std::unique_ptr<TlsConnectionEstablishmentStrategy> mConnectionEstablishmentStrategy{nullptr};
	std::string mHost{}, mPort{};
	std::filesystem::path mCertPath{};
	bool mMustBeHttp2 = false;
	std::chrono::milliseconds mTimeout{20000};
	std::string mLogPrefix{};

	/**
	 * Serializes establishConnection(). It is only needed to protect against connect() and
	 * connectAsync() being called at the same time, which should never happen: connect() is only
	 * used by the legacy client. Remove this mutex along with connect().
	 */
	std::mutex mEstablishConnectionMutex{};

	/* Must be the last field to be deleted first and guarantee all previous fields will be available to the thread on
	 * destruction
	 */
	MustFinishThread mThread;
};

} // namespace flexisip