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

// Fix missing definition of POLLRDHUP.
#if __APPLE__ and !POLLRDHUP
#define POLLRDHUP 0x2000
#endif

#include <filesystem>
#include <fstream>
#include <ostream>
#include <sstream>
#include <thread>

#include <arpa/inet.h>
#include <cmath>
#include <poll.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "flexisip/flexisip-exception.hh"
#include "flexisip/logmanager.hh"
#include "utils/uri-utils.hh"

#include "tls-connection.hh"

using namespace std;

namespace flexisip {

TlsConnection::TlsConnection(const string& host, string_view port, bool mustBeHttp2)
    : mHost{host}, mPort{port}, mMustBeHttp2{mustBeHttp2},
      mLogPrefix{LogManager::makeLogPrefixForInstance(this, "TlsConnection")} {

	mCtx = makeDefaultCtx();
	SSL_CTX_set_verify(mCtx.get(), SSL_VERIFY_NONE, nullptr);
}

TlsConnection::TlsConnection(
    const string& host, string_view port, const string& trustStorePath, const string& certPath, bool mustBeHttp2)
    : mHost{host}, mPort{port}, mCertPath{certPath}, mMustBeHttp2{mustBeHttp2},
      mLogPrefix{LogManager::makeLogPrefixForInstance(this, "TlsConnection")} {

	if (certPath.empty()) {
		mCtx = nullptr;
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

void TlsConnection::connectAsync(su_root_t& root, const function<void()>& onConnectCb) noexcept {
	// SAFETY: The thread MUST NOT outlive `this`;
	mThread = thread{[this, &root, onConnectCb]() { this->doConnectAsync(root, onConnectCb); }};
}

void TlsConnection::doConnectAsync(su_root_t& root, const function<void()>& onConnectCb) {
	connect();

	su_msg_r mamc = SU_MSG_R_INIT;
	if (-1 == su_msg_create(mamc, su_root_task(&root), su_root_task(&root), doConnectCb, sizeof(function<void()>*)))
		throw FlexisipException{mLogPrefix + "could not create auth async message"};

	auto clientOnConnectCb = reinterpret_cast<function<void()>**>(su_msg_data(mamc));
	*clientOnConnectCb = new function<void()>(onConnectCb);

	if (-1 == su_msg_send(mamc))
		throw FlexisipException{mLogPrefix + "could not send auth async message to main thread"};
}

void TlsConnection::doConnectCb([[maybe_unused]] su_root_magic_t* rm, su_msg_r msg, [[maybe_unused]] void* u) {
	auto clientOnConnectCb = *reinterpret_cast<function<void()>**>(su_msg_data(msg));
	(*clientOnConnectCb)();
	delete clientOnConnectCb;
}

/* Add a Server Name Indication (SNI) to the SSL context.
 *
 * > Currently, the only server names supported are DNS hostnames;
 * https://www.rfc-editor.org/rfc/rfc6066#section-3
 *
 * A DNS hostname must follow the syntax described in https://www.rfc-editor.org/rfc/rfc1034#section-3.5 and therefore
 * cannot contain e.g. ':' (to append the port)
 *
 * @param[in] serverName either an IP address (in which case, no SNI is added) or a DNS hostname (roughly, a subset of
 * all the strings matching regex [a-z0-9\.-])
 */
constexpr auto setSNI = [](const auto& ssl, const auto& serverName) {
	using namespace uri_utils;
	const auto* serverNameCStr = serverName.c_str();
	// Connecting to an IP address cannot be ambiguous so not only is there no need to provide an SNI, but furthermore:
	// > Literal IPv4 and IPv6 addresses are not permitted in "HostName".
	// https://www.rfc-editor.org/rfc/rfc6066#section-3
	if (isIpAddress(serverNameCStr)) return 0L;

	return SSL_set_tlsext_host_name(ssl, serverNameCStr);
};

void TlsConnection::connect() noexcept {
	if (isConnected()) return;

	LOGI << "Connecting...";

	if (!mCertPath.empty()) {
		const auto errMsg = loadCertificate();
		if (!errMsg.empty()) {
			LOGE << "Certificate reload error: " << errMsg;
			return;
		}
	}

	/* Create and set up the connection */
	auto hostport = mHost + ":" + mPort;
	SSL* ssl = nullptr;

	BIOUniquePtr newBio{};
	if (isSecured()) {
		newBio = BIOUniquePtr{BIO_new_ssl_connect(mCtx.get())};
		BIO_set_conn_hostname(newBio.get(), hostport.c_str());
		BIO_get_ssl(newBio.get(), &ssl);
		setSNI(ssl, mHost);
		SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
		SSL_set_options(ssl, SSL_OP_ALL);
		if (mMustBeHttp2) {
			unsigned char protos[] = {2, 'h', '2'};
			unsigned int protos_len = sizeof(protos);
			SSL_set_alpn_protos(ssl, protos, protos_len);
		}
	} else {
		// keep the const_cast() here because BIO_new_connect() takes a 'char *' in old revision of OpenSSL.
		newBio = BIOUniquePtr{BIO_new_connect(const_cast<char*>(hostport.c_str()))};
	}
	BIO_set_nbio(newBio.get(), 1);

	/* Ensure that the error queue is empty */
	ERR_clear_error();

	/* Do the connection by actively waiting for connection completion */
	auto status = 0;
	chrono::milliseconds time{0};
	while (status <= 0) {
		const auto proto = isSecured() ? "tls://" : "tcp://";
		const auto errmsg = "Error while connecting to "s + proto + hostport;

		status = isSecured() ? BIO_do_handshake(newBio.get()) : BIO_do_connect(newBio.get());
		if (status <= 0 && !BIO_should_retry(newBio.get())) {
			handleBioError(errmsg, status);
			return;
		}
		if (time >= mTimeout) {
			LOGE << "Timeout: " << errmsg;
			return;
		}

		constexpr chrono::milliseconds sleepDuration{10};
		this_thread::sleep_for(sleepDuration);
		time += sleepDuration;
	}

	/* Check the certificate */
	if (ssl && (SSL_get_verify_mode(ssl) == SSL_VERIFY_PEER && SSL_get_verify_result(ssl) != X509_V_OK)) {
		LOGE << "Certificate verification error: " << X509_verify_cert_error_string(SSL_get_verify_result(ssl));
		return;
	}

	mBio = std::move(newBio);
	LOGI << "Connected";
}

void TlsConnection::disconnect() noexcept {
	mBio.reset();
	LOGI << "Disconnected";
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
	auto fd = getFd();
	if (fd <= 0) return 0;
	struct sockaddr addr{};
	socklen_t addrLen{sizeof(addr)};
	if (getsockname(fd, &addr, &addrLen) < 0) {
		throw system_error{errno, system_category()};
	}
	if (addr.sa_family == AF_INET6) {
		auto in6Addr = reinterpret_cast<sockaddr_in6*>(&addr);
		return ntohs(in6Addr->sin6_port);
	} else if (addr.sa_family == AF_INET) {
		auto inAddr = reinterpret_cast<sockaddr_in*>(&addr);
		return ntohs(inAddr->sin_port);
	} else {
		throw logic_error{"invalid address family ["s + to_string(addr.sa_family) + "]"};
	}
}

int TlsConnection::getFd(BIO& bio) const {
	int fd = 0;
	ERR_clear_error();
	auto status = BIO_get_fd(&bio, &fd);
	if (status < 0) {
		handleBioError(mLogPrefix + ": getting fd from BIO failed", status);
		return -1;
	}
	return fd;
}

int TlsConnection::read(void* data, int dlen) noexcept {
	auto nbBytes = BIO_read(mBio.get(), data, dlen);
	if (nbBytes < 0) {
		if (errno == EWOULDBLOCK || (mBio && BIO_should_retry(mBio.get()))) {
			// Either the socket was emtpy or there wasn't enough data to
			// form a complete TLS message. Return '0' to require the upper
			// code to retry later.
			return 0;
		}
		handleBioError(mLogPrefix + "Error while reading data", nbBytes);
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
	auto nRead = read(data.data(), readSize);
	data.resize(std::max(0, nRead));
	return nRead;
}

int TlsConnection::write(const void* data, int dlen) noexcept {
	ERR_clear_error();
	auto nbBytes = BIO_write(mBio.get(), data, dlen);
	if (nbBytes < 0) {
		if (errno == EWOULDBLOCK || (mBio && BIO_should_retry(mBio.get()))) {
			// Either the socket was full or there wasn't enough space
			// to serialize a complete TLS message. Return '0' to require the
			// upper code to try later.
			return 0;
		}
		handleBioError(mLogPrefix + "Error while writing data", nbBytes);
	}

	return nbBytes;
}

int TlsConnection::write(const char* cStr) noexcept {
	return write(cStr, static_cast<int>(strlen(cStr)));
}

bool TlsConnection::waitForData(chrono::milliseconds timeout) {
	pollfd polls = {0};
	polls.fd = this->getFd();
	polls.events = POLLIN;

	int ret;
	if ((ret = poll(&polls, 1, timeout.count())) < 0) {
		const auto message = mLogPrefix + "Error during poll";
		handleBioError(message, ret);
		throw runtime_error(message);
	}

	return ret != 0;
}

bool TlsConnection::hasData() {
	return waitForData(0ms);
}

void TlsConnection::enableInsecureTestMode() {
	SLOGW << "BE CAREFUL, YOU BETTER BE IN A TESTING ENVIRONMENT, YOU ARE USING AN INSECURE CONNECTION";
	SSL_CTX_set_cert_verify_callback(mCtx.get(), [](auto, auto) { return 1; }, nullptr);
}

TlsConnection::SSLCtxUniquePtr TlsConnection::makeDefaultCtx() {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	// from OpenSSL 1.1.0
	SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
#else
	auto ctx = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
#endif

	return TlsConnection::SSLCtxUniquePtr(ctx);
}

void TlsConnection::handleBioError(const string& msg, int status) const {
	ostringstream os;
	os << msg << ": " << status << " - " << strerror(errno) << " - SSL error stack:";
	ERR_print_errors_cb(
	    [](const char* str, [[maybe_unused]] size_t len, void* u) {
		    auto& os = *static_cast<ostream*>(u);
		    os << endl << '\t' << str;
		    return 0;
	    },
	    &os);
	LOGE << os.str();
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
	int err = BIO_read_filename(certbio, certPath.c_str());
	if (err == 0) {
		LOGE << "BIO_read_filename failed for " << certPath;
		BIO_free_all(certbio);
		return expired;
	}

	X509* cert = PEM_read_bio_X509(certbio, NULL, 0, 0);
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
	BIO* bio = BIO_new(BIO_s_mem());
	if (bio) {
		if (ASN1_TIME_print(bio, time)) write = BIO_read(bio, buffer, buff_length - 1);
		BIO_free_all(bio);
	}
	buffer[write] = '\0';
	return write;
}

} // namespace flexisip