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

#include "tls-connection.hh"

#include <filesystem>
#include <fstream>
#include <thread>

#include <poll.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "flexisip/logmanager.hh"
#include "tls-direct-connection-establishment-strategy.hh"
#include "tls-proxy-connection-establishment-strategy.hh"

using namespace std;

namespace flexisip {

TlsConnection::TlsConnection(const string& host,
                             string_view port,
                             bool mustBeHttp2,
                             const std::optional<HttpsProxyCfg>& httpsProxyCfg)
    : mHost(host), mPort(port), mMustBeHttp2(mustBeHttp2),
      mLogPrefix{LogManager::makeLogPrefixForInstance(this, "TlsConnection")} {

	mCtx = makeDefaultCtx();
	SSL_CTX_set_verify(mCtx.get(), SSL_VERIFY_NONE, nullptr);

	if (httpsProxyCfg.has_value()) {
		mConnectionEstablishmentStrategy = make_unique<TlsProxyConnectionEstablishmentStrategy>(httpsProxyCfg.value());
	} else {
		mConnectionEstablishmentStrategy = make_unique<TlsDirectConnectionEstablishmentStrategy>();
	}
}

TlsConnection::TlsConnection(const string& host,
                             string_view port,
                             const string& trustStorePath,
                             const string& certPath,
                             bool mustBeHttp2,
                             const std::optional<HttpsProxyCfg>& httpsProxyCfg)
    : mHost(host), mPort(port), mCertPath{certPath}, mMustBeHttp2(mustBeHttp2),
      mLogPrefix{LogManager::makeLogPrefixForInstance(this, "TlsConnection")} {

	if (mCertPath.empty()) {
		mCtx = nullptr;
		mConnectionEstablishmentStrategy = make_unique<TlsDirectConnectionEstablishmentStrategy>();
		return;
	}

	mCtx = makeDefaultCtx();
	auto* ctx = mCtx.get();

	if (trustStorePath.empty()) {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
	} else {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
		SSL_CTX_set_cert_verify_callback(ctx, handleVerifyCallback, nullptr);
	}

	if (!SSL_CTX_load_verify_locations(ctx, trustStorePath.empty() ? nullptr : trustStorePath.c_str(),
	                                   "/etc/ssl/certs")) {
		ERR_print_errors_fp(stderr);
		throw CreationError("error while loading trust store");
	}

	const auto errMsg = loadCertificate();
	if (!errMsg.empty()) throw CreationError(errMsg);

	if (httpsProxyCfg.has_value()) {
		mConnectionEstablishmentStrategy = make_unique<TlsProxyConnectionEstablishmentStrategy>(httpsProxyCfg.value());
	} else {
		mConnectionEstablishmentStrategy = make_unique<TlsDirectConnectionEstablishmentStrategy>();
	}
}

TlsConnection::~TlsConnection() {
	BIO_ssl_shutdown(mBio.get());
	mBio.reset();
	mSsl.reset();
	mCtx.reset();
}

string TlsConnection::loadCertificate() {
	// Check certificate (file exists, is readable and still valid).
	if (!filesystem::exists(mCertPath)) {
		return "certificate \"" + mCertPath.string() + "\" does not exist";
	}
	if (fstream certificate{mCertPath, ios_base::in}; !certificate.is_open()) {
		return "cannot open certificate \"" + mCertPath.string() + "\"";
	} else {
		certificate.close();
	}

	auto* ctx = mCtx.get();
	int error = SSL_CTX_use_certificate_file(ctx, mCertPath.c_str(), SSL_FILETYPE_PEM);
	if (error != 1) {
		return "SSL_CTX_use_certificate_file for " + mCertPath.string() + " failed with error " + to_string(error);
	} else if (isCertExpired(mCertPath)) {
		LOGE << "Certificate '" << mCertPath
		     << "' is expired, you will not be able to use it for push notifications: please update your certificate "
		        "or remove it entirely";
	}

	error = SSL_CTX_use_PrivateKey_file(ctx, mCertPath.c_str(), SSL_FILETYPE_PEM);
	if (error != 1 || SSL_CTX_check_private_key(ctx) != 1) {
		return "private key does not match the certificate public key for " + mCertPath.string() + ", error " +
		       to_string(error);
	}

	return "";
}

void TlsConnection::connectAsync(sofiasip::SuRoot& root, const function<void()>& onConnectCb) noexcept {
	// SAFETY: The thread MUST NOT outlive `this`;
	mThread = thread{[this, &root, onConnectCb]() { this->doConnectAsync(root, onConnectCb); }};
}

void TlsConnection::doConnectAsync(sofiasip::SuRoot& root, const function<void()>& onConnectCb) {
	connect();
	root.addToMainLoop(onConnectCb);
}

void TlsConnection::connect() noexcept {
	if (isConnected()) return;

	LOGD << "Connecting...";

	if (!mCertPath.empty()) {
		const auto errMsg = loadCertificate();
		if (!errMsg.empty()) {
			LOGE << "Certificate reload error: " << errMsg;
			return;
		}
	}

	if (auto result = mConnectionEstablishmentStrategy->connect(mCtx, mHost, mPort, mMustBeHttp2, mTimeout);
	    result.has_value()) {
		const lock_guard<mutex> lock(mBioMutex);
		mBio = std::move(result->first);
		mSsl = std::move(result->second);
		LOGD << "Connected";
	}
}

void TlsConnection::disconnect() noexcept {
	mBio.reset();
	mSsl.reset();
	LOGD << "Disconnected";
}

void TlsConnection::resetConnection() noexcept {
	disconnect();
	connect();
}

int TlsConnection::getFd() const noexcept {
	if (mBio == nullptr) {
		return -1;
	}
	return getFd(*mBio);
}

std::uint16_t TlsConnection::getLocalPort() const {
	const auto fd = getFd();
	if (fd <= 0) return 0;
	sockaddr addr{};
	socklen_t addrLen{sizeof(addr)};
	if (getsockname(fd, &addr, &addrLen) < 0) {
		throw system_error{errno, system_category()};
	}
	if (addr.sa_family == AF_INET6) {
		const auto in6Addr = reinterpret_cast<sockaddr_in6*>(&addr);
		return ntohs(in6Addr->sin6_port);
	} else if (addr.sa_family == AF_INET) {
		const auto inAddr = reinterpret_cast<sockaddr_in*>(&addr);
		return ntohs(inAddr->sin_port);
	} else {
		throw logic_error{"invalid address family ["s + to_string(addr.sa_family) + "]"};
	}
}

int TlsConnection::getFd(BIO& bio) const {
	int fd = 0;
	ERR_clear_error();
	if (const auto status = BIO_get_fd(&bio, &fd); status < 0) {
		LOGE << formatBioError(mLogPrefix + ": getting fd from BIO failed", status);
		return -1;
	}
	return fd;
}

int TlsConnection::read(void* data, int dlen) noexcept {
	const auto nbBytes = BIO_read(mBio.get(), data, dlen);
	if (nbBytes < 0) {
		if (errno == EWOULDBLOCK || (mBio && BIO_should_retry(mBio.get()))) {
			// Either the socket was empty or there wasn't enough data to
			// form a complete TLS message. Return '0' to require the upper
			// code to retry later.
			return 0;
		}
		LOGE << formatBioError(mLogPrefix + "Error while reading data", nbBytes);
	}

	if (nbBytes == 0 && mBio) {
		if (BIO_eof(mBio.get())) {
			LOGD << "Disconnect: read EOF, the other end has terminated the connection";
			disconnect();
			return nbBytes;
		}
		if (!BIO_should_retry(mBio.get())) {
			LOGD << "Disconnect: (read) should retry returned false, the connection is closed";
			disconnect();
			return nbBytes;
		}
	}

	return nbBytes;
}

int TlsConnection::read(std::vector<char>& data, int readSize) noexcept {
	data.resize(readSize);
	const auto nRead = read(data.data(), readSize);
	data.resize(std::max(0, nRead));
	return nRead;
}

int TlsConnection::write(const void* data, int dlen) noexcept {
	ERR_clear_error();
	const auto nbBytes = BIO_write(mBio.get(), data, dlen);
	if (nbBytes < 0) {
		if (errno == EWOULDBLOCK || (mBio && BIO_should_retry(mBio.get()))) {
			// Either the socket was full or there wasn't enough space
			// to serialize a complete TLS message. Return '0' to require the
			// upper code to try later.
			return 0;
		}
		LOGE << formatBioError(mLogPrefix + "Error while writing data", nbBytes);
		// If an error occurs and that we know we cannot simply retry, prefer disconnecting right now.
		disconnect();
	}

	return nbBytes;
}

int TlsConnection::write(const char* cStr) noexcept {
	return write(cStr, static_cast<int>(strlen(cStr)));
}

bool TlsConnection::waitForData(const chrono::milliseconds timeout) {
	pollfd polls = {0};
	polls.fd = this->getFd();
	polls.events = POLLIN;

	int ret;
	if ((ret = poll(&polls, 1, timeout.count())) < 0) {
		const auto message = mLogPrefix + "Error during poll";
		LOGE << formatBioError(message, ret);
		throw runtime_error(message);
	}

	return ret != 0;
}

bool TlsConnection::hasData() {
	return waitForData(0ms);
}

void TlsConnection::enableInsecureTestMode() {
	LOGW << "BE CAREFUL, YOU BETTER BE IN A TESTING ENVIRONMENT, YOU ARE USING AN INSECURE CONNECTION";
	SSL_CTX_set_cert_verify_callback(mCtx.get(), [](auto, auto) { return 1; }, nullptr);
}

SSLCtxUniquePtr TlsConnection::makeDefaultCtx() {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	// from OpenSSL 1.1.0
	SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
#else
	auto ctx = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
#endif

	return SSLCtxUniquePtr(ctx);
}

int TlsConnection::handleVerifyCallback(X509_STORE_CTX* ctx, void*) {
	char subject_name[256];

	X509* cert = X509_STORE_CTX_get_current_cert(ctx);
	if (!cert) {
		LOGE_CTX("TlsConnection") << "No certificate found";
		return 0;
	}
	X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
	LOGD_CTX("TlsConnection") << "Verifying " << subject_name;

	int error = X509_STORE_CTX_get_error(ctx);
	if (error != 0) {
		switch (error) {
			case X509_V_ERR_CERT_NOT_YET_VALID:
			case X509_V_ERR_CRL_NOT_YET_VALID:
				LOGE_CTX("TlsConnection")
				    << "Certificate for " << subject_name << " is not yet valid, push notifications will not work";
				break;
			case X509_V_ERR_CERT_HAS_EXPIRED:
			case X509_V_ERR_CRL_HAS_EXPIRED:
				LOGE_CTX("TlsConnection")
				    << "Certificate for " << subject_name << " is expired, push notifications will not work";
				break;
			default: {
				const char* errString = X509_verify_cert_error_string(error);
				LOGE_CTX("TlsConnection")
				    << "Certificate for " << subject_name << " is invalid (reason: " << error << ", "
				    << (errString ? errString : "unknown") << "), push notifications will not work";
				break;
			}
		}
	}

	return 0;
}

bool TlsConnection::isCertExpired(const string& certPath) noexcept {
	bool expired = true;
	BIO* certbio = BIO_new(BIO_s_file());
	if (const int err = BIO_read_filename(certbio, certPath.c_str()); err == 0) {
		LOGE << "BIO_read_filename failed for " << certPath;
		BIO_free_all(certbio);
		return expired;
	}

	X509* cert = PEM_read_bio_X509(certbio, nullptr, 0, 0);
	if (!cert) {
		char buf[128] = {};
		unsigned long error = ERR_get_error();
		ERR_error_string(error, buf);
		LOGE << "Could not parse certificate at " << certPath << ": " << buf;
		BIO_free_all(certbio);
		return expired;
	} else {
		ASN1_TIME* notBefore = X509_get_notBefore(cert);
		ASN1_TIME* notAfter = X509_get_notAfter(cert);
		char beforeStr[128] = {};
		char afterStr[128] = {};
		int validDates = (ASN1_TIME_toString(notBefore, beforeStr, 128) && ASN1_TIME_toString(notAfter, afterStr, 128));
		if (X509_cmp_current_time(notBefore) <= 0 && X509_cmp_current_time(notAfter) >= 0) {
			LOGD << "Certificate " << certPath << " has a valid expiration: " << afterStr;
			expired = false;
		} else {
			// The certificate has an expiry or "not before" value that makes it not valid regarding the server's date.
			if (validDates) {
				LOGD << "Certificate " << certPath << " is expired or not yet valid (not before: " << beforeStr
				     << ", not after: " << afterStr << ")";
			} else {
				LOGD << "Certificate " << certPath << " is expired or not yet valid";
			}
		}
	}
	X509_free(cert);
	BIO_free_all(certbio);

	return expired;
}

int TlsConnection::ASN1_TIME_toString(const ASN1_TIME* time, char* buffer, uint32_t buff_length) {
	int write = 0;
	if (BIO* bio = BIO_new(BIO_s_mem())) {
		if (ASN1_TIME_print(bio, time)) write = BIO_read(bio, buffer, buff_length - 1);
		BIO_free_all(bio);
	}
	buffer[write] = '\0';
	return write;
}

} // namespace flexisip
