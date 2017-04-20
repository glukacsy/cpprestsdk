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
* Contains utility functions for helping to verify server certificates in OS X/iOS.
*
* For the latest on this and related APIs, please see: https://github.com/Microsoft/cpprestsdk
*
* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
****/

#include "stdafx.h"

#include "cpprest/details/x509_cert_utilities.h"

#include <iomanip>

namespace web { namespace http { namespace client { namespace details {

#if defined(__APPLE__) || (defined(ANDROID) || defined(__ANDROID__)) || (defined(_WIN32)  && !defined(__cplusplus_winrt) && !defined(_M_ARM) && !defined(CPPREST_EXCLUDE_WEBSOCKETS)) || defined(__linux__)

#ifndef __linux__

bool is_end_certificate_in_chain(boost::asio::ssl::verify_context &verifyCtx)
{
    X509_STORE_CTX *storeContext = verifyCtx.native_handle();
    int currentDepth = X509_STORE_CTX_get_error_depth(storeContext);
    if (currentDepth != 0)
    {
        return false;
    }
    return true;
}

bool verify_cert_chain_platform_specific(boost::asio::ssl::verify_context &verifyCtx, const std::string &hostName)
{
    if (!is_end_certificate_in_chain(verifyCtx))
    {
        return true;
    }

    X509_STORE_CTX *storeContext = verifyCtx.native_handle();
    STACK_OF(X509) *certStack = X509_STORE_CTX_get_chain(storeContext);
    const int numCerts = sk_X509_num(certStack);
    if (numCerts < 0)
    {
        return false;
    }

    std::vector<std::string> certChain;
    certChain.reserve(numCerts);
    for (int i = 0; i < numCerts; ++i)
    {
        X509 *cert = sk_X509_value(certStack, i);

        // Encode into DER format into raw memory.
        int len = i2d_X509(cert, nullptr);
        if (len < 0)
        {
            return false;
        }

        std::string certData;
        certData.resize(len);
        unsigned char * buffer = reinterpret_cast<unsigned char *>(&certData[0]);
        len = i2d_X509(cert, &buffer);
        if (len < 0)
        {
            return false;
        }

        certChain.push_back(std::move(certData));
    }

    auto verify_result = verify_X509_cert_chain(certChain, hostName);

    // The Windows Crypto APIs don't do host name checks, use Boost's implementation.
#if defined(_WIN32)
    if (verify_result)
    {
        boost::asio::ssl::rfc2818_verification rfc2818(hostName);
        verify_result = rfc2818(verify_result, verifyCtx);
    }
#endif
    return verify_result;
}

#endif

std::vector<std::vector<unsigned char>> get_X509_cert_chain_encoded_data(boost::asio::ssl::verify_context &verifyCtx)
{
    std::vector<std::vector<unsigned char>> cert_chain;

    X509_STORE_CTX *storeContext = verifyCtx.native_handle();

    STACK_OF(X509) *certStack = X509_STORE_CTX_get_chain(storeContext);

    const int numCerts = sk_X509_num(certStack);
    if (numCerts < 0)
    {
        return cert_chain;
    }

    cert_chain.reserve(numCerts);
    for (int index = 0; index < numCerts; ++index)
    {
        X509 *cert = sk_X509_value(certStack, index);
        if (cert)
        {
            unsigned char * certKeyOut = nullptr;
            int resCertificateLength = i2d_X509(cert, &certKeyOut);
            if (resCertificateLength < 0 || !certKeyOut)
            {
                continue;
            }

            std::vector<unsigned char> certOut(certKeyOut, certKeyOut + resCertificateLength);
            cert_chain.emplace_back(certOut);
        }
    }
    return cert_chain;
}

#endif


}}}}
