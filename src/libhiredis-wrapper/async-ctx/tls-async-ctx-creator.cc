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

#include "tls-async-ctx-creator.hh"

#include "exceptions/bad-configuration.hh"
#include "flexisip/logmanager.hh"

using namespace std;

namespace flexisip::redis::async {

void TlsAsyncCtxCreator::SslContextDeleter::operator()(redisSSLContext* sslCtx) noexcept {
	if (sslCtx) redisFreeSSLContext(sslCtx);
}

TlsAsyncCtxCreator::TlsAsyncCtxCreator(const ConnectionParameters& params)
    : mLogPrefix(LogManager::makeLogPrefixForInstance(this, "TlsAsyncCtxCreator")) {
	redisSSLContextError ssl_error = REDIS_SSL_CTX_NONE;
	if (params.connectionType == ConnectionType::tcp) {
		mSslCtx = nullptr;
		return;
	}

	SslContextPtr sslCtx{redisCreateSSLContext(
	    params.tlsCaFile.c_str(), nullptr,
	    params.connectionType == ConnectionType::mutualTls ? params.tlsCert.c_str() : nullptr,
	    params.connectionType == ConnectionType::mutualTls ? params.tlsKey.c_str() : nullptr, nullptr, &ssl_error)};
	if (!sslCtx) {
		throw BadConfiguration{"failed to create SSL context "s + redisSSLContextGetError(ssl_error)};
	}
	mSslCtx = std::move(sslCtx);
}

AsyncContextPtr TlsAsyncCtxCreator::createAsyncCtx(const std::string_view& address, int port) {
	AsyncContextPtr ctx = mAsyncCtxCreator.createAsyncCtx(address, port);

	if (mSslCtx && redisInitiateSSLWithContext(&ctx->c, mSslCtx.get()) != REDIS_OK) {
		LOGE << "Failed to initiate TLS negotiation " << ctx->errstr;
		return nullptr;
	}

	return ctx;
}
} // namespace flexisip::redis::async