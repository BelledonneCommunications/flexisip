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

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <flexisip/common.hh>
#include <flexisip/logmanager.hh>

#include "tls-connection.hh"

using namespace std;

namespace flexisip {

TlsConnection::TlsConnection(const std::string &host, const std::string &port, const SSL_METHOD *method) noexcept
	: mHost{host}, mPort{port} {
	if (method) {
		auto ctx = SSL_CTX_new(method);
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
		mCtx.reset(ctx);
	}
}

TlsConnection::TlsConnection(const std::string &host, const std::string &port, SSLCtxUniquePtr &&ctx) noexcept
	: mCtx{move(ctx)}, mHost{host}, mPort{port} {
}

void TlsConnection::connect() noexcept {
	if (isConnected())
		return;

	/* Create and setup the connection */
	auto hostname = mHost + ":" + mPort;
	SSL *ssl = nullptr;

	BIOUniquePtr newBio{};
	if (isSecured()) {
		newBio = BIOUniquePtr{BIO_new_ssl_connect(mCtx.get())};
		BIO_set_conn_hostname(newBio.get(), hostname.c_str());
		/* Set the SSL_MODE_AUTO_RETRY flag */
		BIO_get_ssl(newBio.get(), &ssl);
		SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
		SSL_set_options(ssl, SSL_OP_ALL);
	} else {
		// keep the const_cast() here because BIO_new_connect() takes a 'char *' in old revision of OpenSSL.
		newBio = BIOUniquePtr{BIO_new_connect(const_cast<char *>(hostname.c_str()))};
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

int TlsConnection::read(void *data, int dlen) noexcept {
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

int TlsConnection::write(const void *data, int dlen) noexcept {
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

void TlsConnection::handleBioError(const std::string &msg, int status) {
	ostringstream os;
	os << msg << ": " << status << " - " << strerror(errno) << " - SSL error stack:";
	ERR_print_errors_cb(
		[](const char *str, size_t len, void *u) {
			auto &os = *static_cast<ostream *>(u);
			os << endl << '\t' << str;
			return 0;
		},
		&os);
	SLOGE << os.str();
}

} // namespace flexisip
