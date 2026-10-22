#pragma once
#include <atomic>
#include <string>

std::wstring inspect_url(std::wstring url, const std::atomic<bool>& cancel);
