#pragma once

#if __has_include(<filesystem>)
#include <filesystem>

#else
// Ubuntu 18.04
#include <experimental/filesystem>
#include "scope-in-experimental.hh"

#endif