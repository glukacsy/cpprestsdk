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
* Contains utility functions for helping to verify server certificates on Windows desktop.
*
* For the latest on this and related APIs, please see: https://github.com/Microsoft/cpprestsdk
*
* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
****/

#include "stdafx.h"

#include "cpprest/details/x509_cert_utilities.h"

#include <type_traits>
#include <wincrypt.h>

namespace web { namespace http { namespace client { namespace details {

// Helper RAII unique_ptrs to free Windows structures.
struct cert_free_certificate_context
{
    void operator()(const CERT_CONTEXT *ctx) const
    {
        CertFreeCertificateContext(ctx);
    }
};
typedef std::unique_ptr<const CERT_CONTEXT, cert_free_certificate_context> cert_context;
struct cert_free_certificate_chain
{
    void operator()(const CERT_CHAIN_CONTEXT *chain) const
    {
        CertFreeCertificateChain(chain);
    }
};
typedef std::unique_ptr<const CERT_CHAIN_CONTEXT, cert_free_certificate_chain> chain_context;

static std::shared_ptr<certificate_info> build_certificate_info_ptr(const chain_context& chain, const std::string& hostName, bool isVerified)
{
    auto info = std::make_shared<certificate_info>(hostName);

    info->verified = isVerified;
    info->certificate_error = chain->TrustStatus.dwErrorStatus;
    info->certificate_chain.reserve((int)chain->cChain);

    for (size_t i = 0; i < chain->cChain; ++i)
    {
        auto pChain = chain->rgpChain[i];
        for (size_t j = 0; j < pChain->cElement; ++j)
        {
            auto chainElement = pChain->rgpElement[j];
            auto cert = chainElement->pCertContext;
            if (cert)
            {
                info->certificate_chain.emplace_back(std::vector<unsigned char>(cert->pbCertEncoded, cert->pbCertEncoded + (int)cert->cbCertEncoded));
            }
        }
    }

    return info;
}

bool verify_X509_cert_chain(const std::vector<std::string> &certChain, const std::string &hostName, const CertificateChainFunction& certInfoFunc /* = nullptr */)
{
    // Create certificate context from server certificate.
    cert_context pCert(CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, reinterpret_cast<const unsigned char *>(certChain[0].c_str()), static_cast<DWORD>(certChain[0].size())));
    if (pCert == nullptr)
    {
        return false;
    }

    // Add all SSL intermediate certs into a store to be used by the OS building the full certificate chain.
    HCERTSTORE caMemStore = NULL;
    caMemStore = CertOpenStore(CERT_STORE_PROV_MEMORY, (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING), NULL, 0, NULL);
    if (caMemStore)
    {
        for (const auto& certData : certChain)
        {
            cert_context certContext(CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, reinterpret_cast<const unsigned char *>(certData.c_str()), static_cast<DWORD>(certData.size())));
            if (certContext)
            {
                CertAddCertificateContextToStore(caMemStore, certContext.get(), CERT_STORE_ADD_ALWAYS, NULL);
            }
        }
    }

    // Let the OS build a certificate chain from the server certificate.
    CERT_CHAIN_PARA params;
    ZeroMemory(&params, sizeof(params));
    params.cbSize = sizeof(CERT_CHAIN_PARA);
    params.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
    LPSTR usages[] =
    {
        szOID_PKIX_KP_SERVER_AUTH,

        // For older servers and to match IE.
        szOID_SERVER_GATED_CRYPTO,
        szOID_SGC_NETSCAPE
    };
    params.RequestedUsage.Usage.cUsageIdentifier = std::extent<decltype(usages)>::value;
    params.RequestedUsage.Usage.rgpszUsageIdentifier = usages;

    PCCERT_CHAIN_CONTEXT pChainContext = {};
    chain_context chain;

    bool isVerified = false;

    auto cSuccess = CertGetCertificateChain(
        nullptr,
        pCert.get(),
        nullptr,
        caMemStore,
        &params,
        CERT_CHAIN_REVOCATION_CHECK_CHAIN,
        nullptr,
        &pChainContext);

    chain.reset(pChainContext);

    if (caMemStore)
    {
        CertCloseStore(caMemStore, 0);
    }

    if (cSuccess && chain)
    {
        // Only do revocation checking if it's known.
        if (chain->TrustStatus.dwErrorStatus == CERT_TRUST_NO_ERROR ||
            chain->TrustStatus.dwErrorStatus == CERT_TRUST_REVOCATION_STATUS_UNKNOWN ||
            chain->TrustStatus.dwErrorStatus == (CERT_TRUST_IS_OFFLINE_REVOCATION | CERT_TRUST_REVOCATION_STATUS_UNKNOWN))
        {
            isVerified = true;
        }

        if (certInfoFunc)
        {
            auto info = build_certificate_info_ptr(chain, hostName, isVerified);

            if (!certInfoFunc(info))
            {
                isVerified = false;
            }
        }
    }
    return isVerified;
}

}}}}