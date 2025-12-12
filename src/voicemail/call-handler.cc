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

#include "call-handler.hh"

#include <filesystem>
#include <fstream>

#include "flexiapi/schemas/account/account.hh"
#include "flexiapi/schemas/voicemail/slot-creation.hh"
#include "flexiapi/schemas/voicemail/slot.hh"
#include "flexisip/utils/sip-uri.hh"
#include "utils/digest.hh"
#include "utils/rand.hh"
#include "utils/string-utils.hh"
#include "utils/transport/http/form-data.hh"
#include "utils/uri-utils.hh"

using namespace std;

namespace {

constexpr auto kMaxReadableSize = 25;
constexpr auto kRandomStringLength = 6;

std::string readAudioFile(const std::filesystem::path& path) {
	if (auto fileSize = filesystem::file_size(path) / 1024 / 1024; fileSize > kMaxReadableSize) {
		throw runtime_error{path.string() + " audio file is too large (" + to_string(fileSize) + "MB)"};
	}

	ifstream f(path);
	constexpr std::size_t readSize{4096};
	f.exceptions(std::ios_base::badbit);

	auto out = string();
	auto buf = string(readSize, '\0');
	while (f.read(&buf[0], readSize)) {
		out.append(buf, 0, f.gcount());
	}
	out.append(buf, 0, f.gcount());

	return out;
}

std::filesystem::path generateRecordName(const std::shared_ptr<linphone::Call>& call) {
	const auto target = call->getRequestAddress()->getParam("target");
	const auto caller = call->getRemoteAddress()->asString();
	flexisip::Random randomGenerator{};
	const auto randomFiller = randomGenerator.string().generate(kRandomStringLength);

	return flexisip::Sha256{}.compute<string>(target + caller + randomFiller) + ".wav";
}

} // namespace

namespace flexisip::voicemail {

void CallHandler::playAnnounce(const std::filesystem::path& announcePath) {
	const auto player = mCall->getPlayer();
	player->addListener(shared_from_this());
	player->open(announcePath);
	player->start();
}

void CallHandler::terminateCall() {
	if (const auto player = mCall->getPlayer(); player) player->removeListener(shared_from_this());

	mCall->removeListener(shared_from_this());
	mCall->terminate();

	notifyCallHandled();
}

void CallHandler::start() {
	mCall->addListener(shared_from_this());
	reserveSlot();
}

void CallHandler::onEofReached(const std::shared_ptr<linphone::Player>& player) {
	switch (mHandlerMode) {
		case HandlerMode::voicemailRecording:
			player->close();
			player->removeListener(shared_from_this());

			mTimer.set(
			    [maybe_thiz = weak_from_this()] {
				    const auto thiz = maybe_thiz.lock();
				    if (!thiz) return;
				    thiz->mCall->sendDtmf('1');

				    thiz->mCall->startRecording();
				    thiz->mTimer.set(
				        [maybe_thiz] {
					        if (const auto thiz = maybe_thiz.lock(); thiz) thiz->mCall->terminate();
				        },
				        thiz->mRecordingParameters.callMaxDuration);
			    },
			    500ms);
			break;
		case HandlerMode::simpleAnnounce:
		default:
			LOGD << "Announce finished, ending call";
			mTimer.set(
			    [maybe_thiz = weak_from_this()] {
				    if (const auto thiz = maybe_thiz.lock(); thiz) thiz->terminateCall();
			    },
			    500ms);
			break;
	}
}

void CallHandler::onAckProcessing(const std::shared_ptr<linphone::Call>&,
                                  const std::shared_ptr<linphone::Headers>&,
                                  bool isReceived) {
	if (!isReceived || mCallState != CallState::establishing) return;
	mCallState = CallState::mediaReady;

	LOGD << "Received ACK, starting to play announce";
	switch (mHandlerMode) {
		case HandlerMode::simpleAnnounce:
			playAnnounce(mAnnouncementsPaths.defaultAnnounce);
			break;
		case HandlerMode::voicemailRecording:
			playAnnounce(mAnnouncementsPaths.voicemailAnnounce);
			break;
		case HandlerMode::unknown:
		default:
			LOGE << "Unknown mode " << static_cast<int>(mHandlerMode) << ", aborting processing";
			terminateCall();
	}
}

void CallHandler::onStateChanged(const std::shared_ptr<linphone::Call>&,
                                 linphone::Call::State state,
                                 const std::string&) {
	switch (state) {
		case linphone::Call::State::StreamsRunning:
			onCallStateStreamsRunning();
			break;
		case linphone::Call::State::End:
			onCallStateEnd();
			break;
		default:
			break;
	}
}

void CallHandler::onCallStateStreamsRunning() {
	if (mCallState == CallState::pending) mCallState = CallState::establishing;
}

void CallHandler::onCallStateEnd() {
	LOGD << "Call ended";

	if (mHandlerMode != HandlerMode::voicemailRecording) {
		notifyCallHandled();
		return;
	}

	mCall->stopRecording();

	mCall->removeListener(shared_from_this());
	if (mCall->getPlayer()) mCall->getPlayer()->removeListener(shared_from_this());

	uploadVoicemail(mRecordingParameters.slotUrl);
}

void CallHandler::handleCallWithoutRecording() {
	mHandlerMode = HandlerMode::simpleAnnounce;
	mCall->accept();
}

void CallHandler::reserveSlot() {
	const auto requestUri = mCall->getRequestAddress();
	const auto targetParameter = uri_utils::unescape(requestUri->getUriParam("target"));
	const auto target = std::string(string_utils::removePrefix(targetParameter, "sip:").value_or(""));

	if (target.empty()) {
		LOGD << "Received request without target parameter, declining call";
		mCall->decline(linphone::Reason::AddressIncomplete);
		notifyCallHandled();
		return;
	}

	LOGD << "Searching for the account ID of the user on the FAM";
	mFlexiApiClient.get(
	    "/api/accounts/"s + target + "/search",
	    [maybe_thiz = weak_from_this(), logPrefix = mLogPrefix](const std::shared_ptr<HttpMessage>&,
	                                                            const std::shared_ptr<HttpResponse>& rep) {
		    const auto thiz = maybe_thiz.lock();
		    if (!thiz) {
			    LOGD_CTX(logPrefix, "reserveSlot") << "Answer received but Call handler is already gone, doing nothing";
			    return;
		    }
		    try {
			    const auto body = nlohmann::json::parse(string(rep->getBody().data(), rep->getBody().size()));
			    const auto account = body.get<flexiapi::Account>();

			    thiz->sendSlotRequest(account.getId());
		    } catch (const exception& e) {
			    LOGE_CTX(logPrefix, "reserveSlot") << "Unexpected error while parsing response: " << e.what();
			    thiz->handleCallWithoutRecording();
		    }
	    },
	    [maybe_thiz = weak_from_this(), logPrefix = mLogPrefix](const std::shared_ptr<HttpMessage>&) {
		    const auto thiz = maybe_thiz.lock();
		    if (!thiz) {
			    LOGD_CTX(logPrefix, "reserveSlot")
			        << "Error while sending account request but call handler is already gone, doing nothing";
			    return;
		    }
		    LOGE_CTX(thiz->mLogPrefix, "reserveSlot") << "Error while sending account request";
		    thiz->handleCallWithoutRecording();
	    });
}

void CallHandler::sendSlotRequest(const int accountId) {
	LOGD << "Reserving a slot to upload a voicemail";
	const nlohmann::json jsonBody(flexiapi::SlotCreation{mCall->getRemoteAddress()->asStringUriOnly(), "audio/wav"});

	mFlexiApiClient.post(
	    "/api/accounts/"s + to_string(accountId) + "/voicemails", jsonBody,
	    [maybe_thiz = weak_from_this(), logPrefix = mLogPrefix](const std::shared_ptr<HttpMessage>&,
	                                                            const std::shared_ptr<HttpResponse>& rep) {
		    const auto thiz = maybe_thiz.lock();
		    if (!thiz) {
			    LOGD_CTX(logPrefix, "sendSlotRequest")
			        << "Answer received but Call Handler is already gone, doing nothing";
			    return;
		    }
		    thiz->onSlotReserved(rep);
	    },
	    [maybe_thiz = weak_from_this()](const std::shared_ptr<HttpMessage>& msg) {
		    const auto thiz = maybe_thiz.lock();
		    if (!thiz) return;
		    auto body = msg->getBody();
		    LOGE_CTX(thiz->mLogPrefix, "reserveSlot") << "Slot reservation failed";

		    thiz->handleCallWithoutRecording();
	    });
}

void CallHandler::onSlotReserved(const std::shared_ptr<HttpResponse>& rep) {
	if (rep->getStatusCode() < 200 || rep->getStatusCode() >= 400) {
		LOGE << "Received an unexpected status code (" << rep->getStatusCode()
		     << "): " << string(rep->getBody().data(), rep->getBody().size());
		handleCallWithoutRecording();
		return;
	}
	if (rep->getStatusCode() >= 300) {
		LOGE << "Status code not handled (" << rep->getStatusCode()
		     << "): " << string(rep->getBody().data(), rep->getBody().size());
		handleCallWithoutRecording();
		return;
	}

	try {
		const auto body = nlohmann::json::parse(string(rep->getBody().data(), rep->getBody().size()));
		const auto slot = body.get<flexiapi::Slot>();
		const string url{slot.getUploadUrl()};
		if (url.empty()) {
			LOGE << "No URL found in answer body to upload the voicemail: " << body;
			handleCallWithoutRecording();
			return;
		}

		mRecordingParameters.slotUrl = sofiasip::Url(string_view(url));

		if (slot.getMaxUploadSize() < mMaxRecordSize) {
			LOGE << "Not enough space available to record a voicemail of "
			     << mRecordingParameters.callMaxDuration.count()
			     << " seconds (available: " << to_string(slot.getMaxUploadSize())
			     << " Bytes / needed: " << mMaxRecordSize << " Bytes)";
			handleCallWithoutRecording();
			return;
		}

		mRecordPath = mRecordingParameters.voicemailStoragePath / generateRecordName(mCall);
		if (filesystem::exists(mRecordPath)) {
			LOGD << "Filename already exists, trying again";
			mRecordPath = mRecordingParameters.voicemailStoragePath / generateRecordName(mCall);
			if (filesystem::exists(mRecordPath)) {
				LOGW << "Cannot record voicemail (a file with the same name already exists): handling the call without "
				        "recording";
				handleCallWithoutRecording();
				return;
			}
		}

		// Accept the call and record voicemail
		LOGD << "Start recording voicemail, storing in " << mRecordPath;
		mHandlerMode = HandlerMode::voicemailRecording;
		auto callParams = mCore->createCallParams(mCall);
		callParams->setRecordFile(mRecordPath);
		mCall->acceptWithParams(callParams);
	} catch (const sofiasip::InvalidUrlError& e) {
		LOGE << "Invalid url (" << e.what() << ")";
		handleCallWithoutRecording();
	} catch (const exception& e) {
		LOGE << "Unexpected error while parsing response: " << e.what();
		handleCallWithoutRecording();
	}
}

void CallHandler::uploadVoicemail(const sofiasip::Url& url) {
	string fileContent{};
	try {
		fileContent = readAudioFile(mRecordPath);
	} catch (exception& e) {
		LOGE << "Failed to read voicemail at " << mRecordPath << " (" << e.what()
		     << "): voicemail will not be uploaded";
		return;
	}

	const HttpHeaders partHeader{
	    {"Content-Disposition", R"(form-data; name="file"; filename=")" + mRecordPath.string() + "\""},
	    {"Content-Type", "audio/wav"},
	};
	const http::MultiPartForm form{{partHeader, fileContent}};

	const auto path = url.getPath();
	mFlexiApiClient.post(
	    !path.empty() ? "/" + path : "", form,
	    [maybe_thiz = weak_from_this(), logPrefix = mLogPrefix](const std::shared_ptr<HttpMessage>&,
	                                                            const std::shared_ptr<HttpResponse>& rep) {
		    const auto thiz = maybe_thiz.lock();
		    int statusCode = rep->getStatusCode();
		    if (!thiz) {
			    LOGD_CTX(logPrefix, "uploadVoicemail") << "Answer received with status (" << statusCode
			                                           << ") but handler is already gone (should not happen)";
			    return;
		    }
		    if (statusCode < 200 || statusCode >= 400) {
			    LOGE_CTX(logPrefix, "uploadVoicemail") << "Upload failed with error (" << statusCode
			                                           << "): " << string(rep->getBody().data(), rep->getBody().size());
		    } else if (statusCode >= 300) {
			    LOGE_CTX(logPrefix, "uploadVoicemail")
			        << "Upload failed: status code not handled (" << statusCode << ")";
		    } else {
			    LOGD_CTX(logPrefix, "uploadVoicemail") << "Upload succeeded";
		    }
		    filesystem::remove(thiz->mRecordPath);
		    thiz->notifyCallHandled();
	    },
	    [maybe_thiz = weak_from_this()](const std::shared_ptr<HttpMessage>&) {
		    const auto thiz = maybe_thiz.lock();
		    if (!thiz) {
			    return;
		    }
		    LOGE_CTX(thiz->mLogPrefix, "uploadVoicemail") << "Upload failed";
		    filesystem::remove(thiz->mRecordPath);
		    thiz->notifyCallHandled();
	    });
}
} // namespace flexisip::voicemail