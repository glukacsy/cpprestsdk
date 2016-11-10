/***
* ==++==
*
* Copyright (c) Microsoft Corporation. All rights reserved.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* ==--==
* =+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
*
* Contains utility functions for helping to verify server certificates in OS X/iOS and Android.
*
* For the latest on this and related APIs, please see: https://github.com/Microsoft/cpprestsdk
*
* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
****/

#pragma once

#include <vector>
#include <string>

#if defined(__APPLE__) || (defined(ANDROID) || defined(__ANDROID__)) || (defined(_WIN32)  && !defined(__cplusplus_winrt) && !defined(_M_ARM) && !defined(CPPREST_EXCLUDE_WEBSOCKETS)) || (defined(__linux__))

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4005)
#endif
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-local-typedef"
#endif
#include <boost/asio/ssl.hpp>
#if defined(__clang__)
#pragma clang diagnostic pop
#endif
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

namespace web { namespace http { namespace client { namespace details {

using namespace utility;

#ifndef __linux__

/// <summary>
/// Using platform specific APIs verifies server certificate.
/// Currently implemented to work on iOS, Android, and OS X.
/// </summary>
/// <param name="verifyCtx">Boost.ASIO context get certificate chain from.</param>
/// <param name="hostName">Host name from the URI.</param>
/// <returns>True if verification passed and server can be trusted, false otherwise.</returns>
bool verify_cert_chain_platform_specific(boost::asio::ssl::verify_context &verifyCtx, const std::string &hostName);

bool verify_X509_cert_chain(const std::vector<std::string> &certChain, const std::string &hostName);

#endif

using PinningCallBackFunction = std::function<bool(const std::string&, const std::string&)>;
using RejectedCertsCallback = std::function<void(json::value)>;

bool is_certificate_pinned(const std::string& host, boost::asio::ssl::verify_context &verifyCtx, PinningCallBackFunction pinningCallback, RejectedCertsCallback rejectedCertsCallback = nullptr);

json::value get_cert_chain_information(boost::asio::ssl::verify_context &verifyCtx);

utility::string_t get_fingerprint_from_cert(const X509* cert);

utility::string_t get_subject_from_cert(X509* cert);

utility::string_t get_issuer_from_cert(X509* cert);

}}}}

#endif
