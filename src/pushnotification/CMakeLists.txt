############################################################################
# CMakeLists.txt
# Copyright (C) 2010-2023 Belledonne Communications, Grenoble France
#
############################################################################
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#
############################################################################

target_sources(flexisip PRIVATE
	access-token-provider.hh
	apple/apple-client.cc apple/apple-client.hh
	apple/apple-request.cc apple/apple-request.hh
	client.cc client.hh
	contact-expiration-notifier.cc contact-expiration-notifier.hh
	firebase/firebase-client.cc firebase/firebase-client.hh
	firebase-v1/firebase-v1-client.cc firebase-v1/firebase-v1-client.hh
	firebase/firebase-request.cc firebase/firebase-request.hh
	firebase-v1/firebase-v1-access-token-provider.cc firebase-v1/firebase-v1-access-token-provider.hh
	firebase-v1/firebase-v1-authentication-manager.cc firebase-v1/firebase-v1-authentication-manager.hh
	firebase-v1/firebase-v1-request.cc firebase-v1/firebase-v1-request.hh
	generic/generic-http2-client.cc generic/generic-http2-client.hh
	generic/generic-http2-request.cc generic/generic-http2-request.hh
	generic/generic-http-client.cc generic/generic-http-client.hh
	generic/generic-http-request.cc generic/generic-http-request.hh
	generic/generic-utils.cc generic/generic-utils.hh
	legacy/legacy-client.cc legacy/legacy-client.hh
	pushnotification-context.cc pushnotification-context.hh
	push-info.cc push-info.hh
	push-param.cc push-param.hh
	push-type.cc push-type.hh
	request.cc request.hh
	rfc8599-push-params.cc rfc8599-push-params.hh
	service.cc service.hh
	strategy/remote-push-strategy.cc strategy/remote-push-strategy.hh
	strategy/strategy.cc strategy/strategy.hh
)