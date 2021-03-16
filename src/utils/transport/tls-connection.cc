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

#include <limits>
#include <ostream>
#include <sstream>

#include <poll.h>

#include <nghttp2/nghttp2.h>
#include <nghttp2/nghttp2ver.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <flexisip/common.hh>
#include <flexisip/logmanager.hh>

#include "tls-connection.hh"

using namespace std;

namespace flexisip {

TlsConnection::TlsConnection(const string& host, const string& port, bool mustBeHttp2) noexcept
	: mHost{host}, mPort{port}, mMustBeHttp2{mustBeHttp2} {

	auto ctx = getDefaultCtx();
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	mCtx.reset(ctx);
}

TlsConnection::TlsConnection(const string& host, const string& port, const string& trustStorePath,
							 const string& certPath, bool mustBeHttp2)
	: mHost{host}, mPort{port}, mMustBeHttp2{mustBeHttp2} {

	if (certPath.empty()) {
		mCtx = nullptr;
		return;
	}

	auto ctx = getDefaultCtx();

	if (trustStorePath.empty()) {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	} else {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
		SSL_CTX_set_cert_verify_callback(ctx, handleVerifyCallback, NULL);
	}

	if (!SSL_CTX_load_verify_locations(ctx, trustStorePath.empty() ? NULL : trustStorePath.c_str(), "/etc/ssl/certs")) {
		SLOGE << "Error loading trust store";
		ERR_print_errors_fp(stderr);
		throw runtime_error("Error during TlsConnection creation");
	}

	if (!certPath.empty()) {
		int error = SSL_CTX_use_certificate_file(ctx, certPath.c_str(), SSL_FILETYPE_PEM);
		if (error != 1) {
			LOGE("SSL_CTX_use_certificate_file for %s failed: %d", certPath.c_str(), error);
			throw runtime_error("Error during TlsConnection creation");
		} else if (isCertExpired(certPath)) {
			LOGEN("Certificate %s is expired! You won't be able to use it for push notifications. Please update your "
				  "certificate or remove it entirely.",
				  certPath.c_str());
		}
	}
	if (!certPath.empty()) {
		int error = SSL_CTX_use_PrivateKey_file(ctx, certPath.c_str(), SSL_FILETYPE_PEM);
		if (error != 1 || SSL_CTX_check_private_key(ctx) != 1) {
			SLOGE << "Private key does not match the certificate public key for " << certPath << ": " << error;
			throw runtime_error("Error during TlsConnection creation");
		}
	}

	mCtx.reset(ctx);
}

void TlsConnection::connect() noexcept {
	if (isConnected())
		return;

	/* Create and setup the connection */
	auto hostname = mHost + ":" + mPort;
	SSL* ssl = nullptr;

	BIOUniquePtr newBio{};
	if (isSecured()) {
		newBio = BIOUniquePtr{BIO_new_ssl_connect(mCtx.get())};
		BIO_set_conn_hostname(newBio.get(), hostname.c_str());
		/* Set the SSL_MODE_AUTO_RETRY flag */
		BIO_get_ssl(newBio.get(), &ssl);
		SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
		SSL_set_options(ssl, SSL_OP_ALL);
		if (mMustBeHttp2) {
			unsigned char protos[] = {2, 'h', '2'};
			unsigned int protos_len = sizeof(protos);
			SSL_set_alpn_protos(ssl, protos, protos_len);
		}
	} else {
		// keep the const_cast() here because BIO_new_connect() takes a 'char *' in old revision of OpenSSL.
		newBio = BIOUniquePtr{BIO_new_connect(const_cast<char*>(hostname.c_str()))};
	}

	ERR_clear_error();

	auto sat = BIO_do_connect(newBio.get());
	if (sat <= 0) {
		handleBioError("Error attempting to connect to " + hostname, sat);
		return;
	}

	if (isSecured()) {
		sat = BIO_do_handshake(newBio.get());
		if (sat <= 0) {
			handleBioError("Error attempting to handshake to " + hostname, sat);
			return;
		}
	}

	/* Check the certificate */
	if (ssl && (SSL_get_verify_mode(ssl) == SSL_VERIFY_PEER && SSL_get_verify_result(ssl) != X509_V_OK)) {
		SLOGE << "Certificate verification error: " << X509_verify_cert_error_string(SSL_get_verify_result(ssl));
		return;
	}

	mBio = move(newBio);
}

void TlsConnection::resetConnection() noexcept {
	disconnect();
	connect();
}

int TlsConnection::getFd() const noexcept {
	int fd;
	if (mBio == nullptr)
		return -1;
	ERR_clear_error();
	auto status = BIO_get_fd(mBio.get(), &fd);
	if (status < 0) {
		handleBioError("TlsConnection: getting fd from BIO failed. ", status);
		return -1;
	}
	return fd;
}

int TlsConnection::read(void* data, int dlen) noexcept {
	ERR_clear_error();
	auto nread = BIO_read(mBio.get(), data, dlen);
	if (nread < 0) {
		if (BIO_should_retry(mBio.get()))
			return 0;
		ostringstream err{};
		err << "TlsConnection[" << this << "]: error while reading data. ";
		handleBioError(err.str(), nread);
	}
	return nread;
}

int TlsConnection::write(const void* data, int dlen) noexcept {
	ERR_clear_error();
	auto nwritten = BIO_write(mBio.get(), data, dlen);
	if (nwritten < 0) {
		if (BIO_should_retry(mBio.get()))
			return 0;
		ostringstream err{};
		err << "TlsConnection[" << this << "]: error while writting data. ";
		handleBioError(err.str(), nwritten);
	}
	return nwritten;
}

bool TlsConnection::waitForData(int timeout) const {
	int fdSocket;
	ERR_clear_error();
	if (BIO_get_fd(getBIO(), &fdSocket) < 0) {
		ERR_clear_error();
		throw runtime_error("no associated socket");
	}

	pollfd polls = {0};
	polls.fd = fdSocket;
	polls.events = POLLIN;

	int ret;
	if ((ret = poll(&polls, 1, timeout)) < 0) {
		throw runtime_error(string{"poll() failed: "} + strerror(errno));
	}
	return ret != 0;
}

SSL_CTX* TlsConnection::getDefaultCtx() {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	// from OpenSSL 1.1.0
	SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
#else
	auto ctx = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
#endif

	return ctx;
}

void TlsConnection::handleBioError(const string& msg, int status) {
	ostringstream os;
	os << msg << ": " << status << " - " << strerror(errno) << " - SSL error stack:";
	ERR_print_errors_cb(
		[](const char* str, size_t len, void* u) {
			auto& os = *static_cast<ostream*>(u);
			os << endl << '\t' << str;
			return 0;
		},
		&os);
	SLOGE << os.str();
}

int TlsConnection::handleVerifyCallback(X509_STORE_CTX* ctx, void* ud) {
	char subject_name[256];

	X509* cert = X509_STORE_CTX_get_current_cert(ctx);
	if (!cert) {
		SLOGE << "No certificate found!";
		return 0;
	}
	X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
	SLOGD << "Verifying " << subject_name;

	int error = X509_STORE_CTX_get_error(ctx);
	if (error != 0) {
		switch (error) {
			case X509_V_ERR_CERT_NOT_YET_VALID:
			case X509_V_ERR_CRL_NOT_YET_VALID:
				SLOGE << "Certificate for " << subject_name << " is not yet valid. Push won't work.";
				break;
			case X509_V_ERR_CERT_HAS_EXPIRED:
			case X509_V_ERR_CRL_HAS_EXPIRED:
				SLOGE << "Certificate for " << subject_name << " is expired. Push won't work.";
				break;
			default: {
				const char* errString = X509_verify_cert_error_string(error);
				SLOGE << "Certificate for " << subject_name << " is invalid (reason: " << error << ": "
					  << (errString ? errString : "unknown") << "). Push won't work.";
				break;
			}
		}
	}

	return 0;
}

bool TlsConnection::isCertExpired(const std::string& certPath) noexcept {
	bool expired = true;
	BIO* certbio = BIO_new(BIO_s_file());
	int err = BIO_read_filename(certbio, certPath.c_str());
	if (err == 0) {
		LOGE("BIO_read_filename failed for %s", certPath.c_str());
		BIO_free_all(certbio);
		return expired;
	}

	X509* cert = PEM_read_bio_X509(certbio, NULL, 0, 0);
	if (!cert) {
		char buf[128] = {};
		unsigned long error = ERR_get_error();
		ERR_error_string(error, buf);
		LOGE("Couldn't parse certificate at %s : %s", certPath.c_str(), buf);
		BIO_free_all(certbio);
		return expired;
	} else {
		ASN1_TIME* notBefore = X509_get_notBefore(cert);
		ASN1_TIME* notAfter = X509_get_notAfter(cert);
		char beforeStr[128] = {};
		char afterStr[128] = {};
		int validDates = (ASN1_TIME_toString(notBefore, beforeStr, 128) && ASN1_TIME_toString(notAfter, afterStr, 128));
		if (X509_cmp_current_time(notBefore) <= 0 && X509_cmp_current_time(notAfter) >= 0) {
			LOGD("Certificate %s has a valid expiration: %s.", certPath.c_str(), afterStr);
			expired = false;
		} else {
			// the certificate has an expire or not before value that makes it not valid regarding the server's date.
			if (validDates) {
				LOGD("Certificate %s is expired or not yet valid! Not Before: %s, Not After: %s", certPath.c_str(),
					 beforeStr, afterStr);
			} else {
				LOGD("Certificate %s is expired or not yet valid!", certPath.c_str());
			}
		}
	}
	X509_free(cert);
	BIO_free_all(certbio);

	return expired;
}

/* Utility function to convert ASN1_TIME to a printable string in a buffer */
int TlsConnection::ASN1_TIME_toString(const ASN1_TIME* time, char* buffer, uint32_t buff_length) {
	int write = 0;
	BIO* bio = BIO_new(BIO_s_mem());
	if (bio) {
		if (ASN1_TIME_print(bio, time))
			write = BIO_read(bio, buffer, buff_length - 1);
		BIO_free_all(bio);
	}
	buffer[write] = '\0';
	return write;
}

} // namespace flexisip