############################################################################
# CMakeLists.txt
# Copyright (C) 2010-2025 Belledonne Communications, Grenoble France
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
############################################################################

target_sources(flexisip PRIVATE
	module-auth.cc
	module-authentication-base.cc
	module-auth-trusted-hosts.cc module-auth-trusted-hosts.hh
	module-authorization.cc module-authorization.hh
	module-capabilities.cc module-capabilities.hh
	module-contact-route-inserter.cc
	module-forward.cc module-forward.hh
	module-garbage-in.cc
	module-gatewayadapter.cc
	module-loadbalancer.cc
	module-mediarelay.cc
	module-nat-helper.cc module-nat-helper.hh
	module-redirect.cc
	module-presence.cc
	module-pushnotification.cc module-pushnotification.hh
	module-regevent.cc
	module-registrar.cc
	module-router.cc
	module-sanitychecker.cc
	module-statistics-collector.cc
	module-toolbox.cc module-toolbox.hh
	module-transcode.cc module-transcode.hh
	module.cc
)

if(ENABLE_OPENID_CONNECT)
	target_sources(flexisip PRIVATE
		module-auth-openid-connect.cc module-auth-openid-connect.hh
	)
endif()

if(ENABLE_B2BUA)
	target_sources(flexisip PRIVATE
		module-b2bua.cc
	)
endif()
