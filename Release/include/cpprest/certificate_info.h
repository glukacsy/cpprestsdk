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
* Certificate info
*
* For the latest on this and related APIs, please see: https://github.com/Microsoft/cpprestsdk
*
* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
****/

#pragma once

#include <vector>
#include <string>

namespace web { namespace http { namespace client {

struct certificate_info
{
    std::vector<std::vector<unsigned char>> certificate_chain;
    std::string host_name;
    long certificate_error{ 0 };
    bool verified{ false };

    certificate_info(const std::string host) : host_name(host) {};
    certificate_info(const std::string host, std::vector<std::vector<unsigned char>> chain, long error = 0) : host_name(host), certificate_chain(chain), certificate_error(error){};
    certificate_info(const bool verified) : verified(verified) {};
};

using CertificateChainFunction = std::function<bool(const std::shared_ptr<certificate_info> certificate_Info)>;

}}}