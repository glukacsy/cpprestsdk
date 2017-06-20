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
* Contains utility functions for helping to verify server certificates on OSX/iOS.
*
* For the latest on this and related APIs, please see: https://github.com/Microsoft/cpprestsdk
*
* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
****/

#include "stdafx.h"

#include "cpprest/details/x509_cert_utilities.h"

#include <CoreFoundation/CFData.h>
#include <Security/SecBase.h>
#include <Security/SecCertificate.h>
#include <Security/SecPolicy.h>
//#include <Security/Security.h>
#include <Security/SecTrust.h>

namespace web { namespace http { namespace client { namespace details {

// Simple RAII pattern wrapper to perform CFRelease on objects.
template <typename T>
class cf_ref
{
public:
    cf_ref(T v) : value(v)
    {
        static_assert(sizeof(cf_ref<T>) == sizeof(T), "Code assumes just a wrapper, see usage in CFArrayCreate below.");
    }
    cf_ref() : value(nullptr) {}
    cf_ref(cf_ref &&other) : value(other.value) { other.value = nullptr; }

    ~cf_ref()
    {
        if(value != nullptr)
        {
            CFRelease(value);
        }
    }

    T & get()
    {
        return value;
    }
private:
    cf_ref(const cf_ref &);
    cf_ref & operator=(const cf_ref &);
    T value;
};

bool verify_X509_cert_chain(const std::vector<std::string> &certChain, const std::string &hostName, const CertificateChainFunction& certInfoFunc /* = nullptr */)
{
    // Build up CFArrayRef with all the certificates.
    // All this code is basically just to get into the correct structures for the Apple APIs.
    // Copies are avoided whenever possible.
    std::vector<cf_ref<SecCertificateRef>> certs;
    for (const auto & certBuf : certChain)
    {
        cf_ref<CFDataRef> certDataRef = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault,
            reinterpret_cast<const unsigned char*>(certBuf.c_str()),
            certBuf.size(),
            kCFAllocatorNull);
        if (certDataRef.get() == nullptr)
        {
            return false;
        }

        cf_ref<SecCertificateRef> certObj = SecCertificateCreateWithData(nullptr, certDataRef.get());
        if (certObj.get() == nullptr)
        {
            return false;
        }
        certs.push_back(std::move(certObj));
    }
    cf_ref<CFArrayRef> certsArray = CFArrayCreate(kCFAllocatorDefault, const_cast<const void **>(reinterpret_cast<void **>(&certs[0])), certs.size(), nullptr);
    if (certsArray.get() == nullptr)
    {
        return false;
    }

    // Create trust management object with certificates and SSL policy.
    // Note: SecTrustCreateWithCertificates expects the certificate to be
    // verified is the first element.
    cf_ref<CFStringRef> cfHostName = CFStringCreateWithCStringNoCopy(kCFAllocatorDefault,
        hostName.c_str(),
        kCFStringEncodingASCII,
        kCFAllocatorNull);
    if (cfHostName.get() == nullptr)
    {
        return false;
    }

    cf_ref<SecPolicyRef> policy = SecPolicyCreateSSL(true /* client side */, cfHostName.get());
    cf_ref<SecTrustRef> trust;
    OSStatus status = SecTrustCreateWithCertificates(certsArray.get(), policy.get(), &trust.get());

    bool isVerified = false;
    if (status == noErr)
    {
        // Perform actual certificate verification.
        SecTrustResultType trustResult;
        status = SecTrustEvaluate(trust.get(), &trustResult);
        if (status == noErr && (trustResult == kSecTrustResultUnspecified || trustResult == kSecTrustResultProceed))
        {
            isVerified = true;
        }

        if (certInfoFunc)
        {
            auto info = std::make_shared<certificate_info>(hostName);
            info->certificate_error = (long)status;
            info->verified = isVerified;

            // Get the full certificate chain.
            CFArrayRef certificates = NULL;
            auto sStatus = SecTrustCopyCustomAnchorCertificates(trust.get(), &certificates);
            if (sStatus == noErr)
            {
                CFIndex cnt = CFArrayGetCount(certificates);

                std::vector<std::vector<unsigned char>> full_cert_chain(cnt);
                for (int i = 0; i < cnt; i++)
                {
                    SecCertificateRef cert = SecTrustGetCertificateAtIndex(trust.get(), i);
                    CFDataRef cdata = SecCertificateCopyData(cert);

                    const unsigned char * buffer = CFDataGetBytePtr(cdata);
                    full_cert_chain.emplace_back(std::vector<unsigned char>(buffer, buffer + CFDataGetLength(cdata)));
                }
                info->certificate_chain = full_cert_chain;
            }

            if (!certInfoFunc(info))
            {
                isVerified = false;
            }
        }
    }
    return isVerified;
}

}}}}
