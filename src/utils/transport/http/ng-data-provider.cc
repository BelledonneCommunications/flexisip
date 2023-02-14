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

#include "ng-data-provider.hh"

namespace flexisip {

NgDataProvider::NgDataProvider(const std::vector<char>& data) noexcept {
	mDataProv.source.ptr = this;
	mDataProv.read_callback = []([[maybe_unused]] nghttp2_session* session, [[maybe_unused]] int32_t stream_id, uint8_t* buf, size_t length,
	                             uint32_t* data_flags, nghttp2_data_source* source, [[maybe_unused]] void* user_data) noexcept {
		return static_cast<NgDataProvider*>(source->ptr)->read(buf, length, data_flags);
	};
	mData.write(data.data(), data.size());
}

NgDataProvider::NgDataProvider(const std::string& data) noexcept {
	mDataProv.source.ptr = this;
	mDataProv.read_callback = []([[maybe_unused]] nghttp2_session* session, [[maybe_unused]] int32_t stream_id, uint8_t* buf, size_t length,
	                             uint32_t* data_flags, nghttp2_data_source* source, [[maybe_unused]] void* user_data) noexcept {
		return static_cast<NgDataProvider*>(source->ptr)->read(buf, length, data_flags);
	};
	mData.write(data.data(), data.size());
}

ssize_t NgDataProvider::read(uint8_t* buf, size_t length, uint32_t* data_flags) noexcept {
	*data_flags = 0;
	mData.read(reinterpret_cast<char*>(buf), length);
	if (mData.eof())
		*data_flags |= NGHTTP2_DATA_FLAG_EOF;
	if (!mData.good() && !mData.eof())
		return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
	return mData.gcount();
}

} /* namespace flexisip */
