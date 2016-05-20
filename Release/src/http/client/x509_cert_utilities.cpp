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

#if defined(__APPLE__) || (defined(ANDROID) || defined(__ANDROID__)) || (defined(_WIN32)  && !defined(__cplusplus_winrt) && !defined(_M_ARM) && !defined(CPPREST_EXCLUDE_WEBSOCKETS))
bool verify_cert_chain_platform_specific(boost::asio::ssl::verify_context &verifyCtx, const std::string &hostName)
{
    X509_STORE_CTX *storeContext = verifyCtx.native_handle();
    int currentDepth = X509_STORE_CTX_get_error_depth(storeContext);
    if (currentDepth != 0)
    {
        return true;
    }

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

std::string get_public_key_from_cert(X509* cert)
{
    std::string result;

    EVP_PKEY *pKey =  X509_get_pubkey(cert);
    
    if(!pKey)
    {
        return result;
    }

    std::size_t keyLen = i2d_PublicKey(pKey, NULL);

    if(keyLen > 0)
    {
        std::vector<unsigned char> buf(keyLen, 0x00);

        unsigned char *buffer = &buf[0];

        i2d_PublicKey(pKey, &buffer);

        std::stringstream ssResult;

        ssResult << std::hex;

        for(auto value: buf)
        {
            ssResult << std::setw(2) << std::setfill('0') << (int) (value);
        }

        result = ssResult.str();
    }

    EVP_PKEY_free(pKey);

    return result; 
}
    
std::vector<std::string> get_cert_chain_public_keys(boost::asio::ssl::verify_context &verifyCtx)
{
    std::vector<std::string> certChain;
 
    X509_STORE_CTX *storeContext = verifyCtx.native_handle();
    int currentDepth = X509_STORE_CTX_get_error_depth(storeContext);
    if (currentDepth != 0)
    {
        return certChain;
    }
    
    STACK_OF(X509) *certStack = X509_STORE_CTX_get_chain(storeContext);
    const int numCerts = sk_X509_num(certStack);
    if (numCerts < 0)
    {
        return certChain;
    }
    
    certChain.reserve(numCerts);

    for (int i = 0; i < numCerts; ++i)
    {
        X509 *cert = sk_X509_value(certStack, i);
        
        certChain.push_back(get_public_key_from_cert(cert));
    }
    
    return certChain;
}

PinningResult is_certificate_pinned(const std::string& host, boost::asio::ssl::verify_context &verifyCtx, PinningCallBackFunction pinningCallback)
{
    PinningResult result = PinningResult::NoKeys;

    auto cert_chain_public_keys = web::http::client::details::get_cert_chain_public_keys(verifyCtx);

    if (!cert_chain_public_keys.empty())
    {
        result = PinningResult::NotPinned;

        for (const auto& key : cert_chain_public_keys)
        {
            if (pinningCallback(host, key))
            {
                result = PinningResult::Pinned;

                break;
            }
        }
    }

    return result;
}

#endif

}}}}
