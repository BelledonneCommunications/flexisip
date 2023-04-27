/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <chrono>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <variant>

#include <sys/wait.h>
#include <unistd.h>

#include "flexisip-config.h"
#include "utils/pipe.hh"
#include "utils/sys-err.hh"
#include "utils/variant-utils.hh"

#include "posix-process.hh"

using namespace std;

namespace flexisip {
namespace process {

Process::Process(function<void()>&& f)
    : mState([&f]() -> State {
	      class Child {
		  public:
		      pipe::ReadOnly mStdin;
		      pipe::WriteOnly mStdout;
		      pipe::WriteOnly mStderr;
	      };

	      auto forked = visit(
	          [](auto&& in, auto&& out, auto&& err) -> variant<SysErr, Child, Running> {
		          if constexpr (is_same_v<decay_t<decltype(in)>, SysErr>) return in;
		          else if constexpr (is_same_v<decay_t<decltype(out)>, SysErr>) return out;
		          else if constexpr (is_same_v<decay_t<decltype(err)>, SysErr>) return err;
		          else {
			          auto pid = ::fork();
			          if (pid < 0) return SysErr();

			          // Forking dupes all descriptors, which means e.g. the write end of stdin will be held by both the
			          // parent and the child, so if the parent closes it, the child would not detect it.
			          // We have to close the (ir)relevent descs in the parent and the child

			          if (0 < pid) return Running(move(in), move(out), move(err), pid);

			          return Child{move(in), move(out), move(err)};
		          }
	          },
	          pipe::open(), pipe::open(), pipe::open());
	      // This 2-step init ensures that the destructors of the appropriate descriptors are called on the child
	      return visit(
	          [&f](auto&& forked) -> State {
		          if constexpr (is_same_v<decay_t<decltype(forked)>, Child>) {
			          if (auto error = forked.mStdin.duplicateTo(STDIN_FILENO)) {
				          cerr << "Failed to bind child's stdin to parent's pipe: " << *error;
				          ::exit(EXIT_FAILURE);
			          }
			          if (auto error = forked.mStdout.duplicateTo(STDOUT_FILENO)) {
				          cerr << "Failed to bind child's stdout to parent's pipe: " << *error;
				          ::exit(EXIT_FAILURE);
			          }
			          if (auto error = forked.mStderr.duplicateTo(STDERR_FILENO)) {
				          cerr << "Failed to bind child's stderr to parent's pipe: " << *error;
				          ::exit(EXIT_FAILURE);
			          }

			          f();

			          /* From fork()'s manual:
			           * "The child process is created with a single thread […] including the states of mutexes,
			           * condition variables, and other pthreads objects"
			           * Meaning destructors waiting on shared state are very likely to deadlock, so we cannot just
			           * ::exit() as usual.
			           */
			          ::execl(DUMMY_EXEC, DUMMY_EXEC, nullptr);
			          throw runtime_error{"unreachable"};
		          } else {
			          return move(forked);
		          }
	          },
	          move(forked));
      }()) {
}

void Process::_wait(int noHang) {
	try {
		auto& process = std::get<Running>(mState);
		int wStatus = 0;
		auto wPid = ::waitpid(process.mPid, &wStatus, noHang);
		if (wPid < 0) {
			mState = SysErr();
			return;
		}
		if (wPid == 0) return; // Still Running
		if (WIFEXITED(wStatus)) {
			mState = ExitedNormally(move(process), static_cast<uint8_t>(WEXITSTATUS(wStatus)));
			return;
		}
		mState = Unexpected();
	} catch (std::bad_variant_access const&) {
		return;
	}
}

State& Process::state() {
	_wait(WNOHANG);
	return mState;
}

// TODO: The timeout mechanism is an inaccurate semi-busy loop.
// A better timeout could be implemented with a self-pipe trick
std::variant<Unexpected, TimeOut, ExitedNormally, SysErr> Process::wait(chrono::milliseconds timeout) && {
	class EscapeHatch {};
	constexpr auto step = 100ms;
	for (auto _ = 0ms; _ < timeout; _ += step) {
		_wait(WNOHANG);
		try {
			return visit(
			    [](auto&& state) -> std::variant<Unexpected, TimeOut, ExitedNormally, SysErr> {
				    if constexpr (is_same_v<decay_t<decltype(state)>, Running>) {
					    throw EscapeHatch{};
				    } else {
					    return move(state);
				    }
			    },
			    move(mState));
		} catch (const EscapeHatch&) {
			this_thread::sleep_for(step);
		}
	}

	auto& state = std::get<Running>(mState);
	cerr << "Timed out waiting for " << *this << "\n";
	if (auto* out = get_if<pipe::ReadOnly>(&state.mStdout))
		cerr << "stdout: " << StreamableVariant(out->read(0xFFFF)) << "\n";
	if (auto* err = get_if<pipe::ReadOnly>(&state.mStderr))
		cerr << "stderr: " << StreamableVariant(err->read(0xFFFF)) << "\n";
	return TimeOut{timeout};
}

optional<SysErr> Running::signal(SigNum sig) {
	if (::kill(mPid, sig) < 0) return SysErr();
	return {};
}

ostream& operator<<(ostream& stream, const Process& process) {
	return stream << "Process{mState: " << StreamableVariant(process.mState) << "}";
}

ostream& operator<<(ostream& stream, const ExitedNormally& state) {
	return stream << "process::ExitedNormally{mExitCode: " << int(state.mExitCode)
	              << ", mStdout: " << StreamableVariant(state.mStdout) << ", mStderr: " << StreamableVariant(state.mStderr)
	              << "}";
}
ostream& operator<<(ostream& stream, ExitedNormally&& state) {
	return stream << "process::ExitedNormally{mExitCode: " << int(state.mExitCode)
	              << ", mStdout: " << StreamableVariant(move(state.mStdout))
	              << ", mStderr: " << StreamableVariant(move(state.mStderr)) << "}";
}

ostream& operator<<(ostream& stream, const Running& state) {
	return stream << "process::Running{mPid: " << state.mPid << ", mStdin: " << StreamableVariant(state.mStdin)
	              << ", mStdout: " << StreamableVariant(state.mStdout) << ", mStderr: " << StreamableVariant(state.mStderr)
	              << "}";
}
ostream& operator<<(ostream& stream, Running&& state) {
	return stream << "process::Running{mPid: " << state.mPid << ", mStdin: " << StreamableVariant(state.mStdin)
	              << ", mStdout: " << StreamableVariant(move(state.mStdout))
	              << ", mStderr: " << StreamableVariant(move(state.mStderr)) << "}";
}

ostream& operator<<(ostream& stream, const Unexpected&) {
	return stream << "process::Unexpected()";
}

} // namespace process
} // namespace flexisip
