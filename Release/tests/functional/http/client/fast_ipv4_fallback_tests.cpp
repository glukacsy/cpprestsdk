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
 * Tests cases for fast_ipv4_fallback
 *
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 ****/

#ifndef _WIN32

#include "stdafx.h"
#include "cpprest/details/fast_ipv4_fallback.h"

using namespace web::http;
using namespace web::http::client;
using namespace tests::functional::http::utilities;

namespace tests { namespace functional { namespace http { namespace client {
    using Iterator = boost::asio::ip::tcp::resolver::iterator;
    using boost::asio::detail::addrinfo_type;
    
    class EndpointInfo
    {
    public:
        
        enum Type {unknown, ipv4, ipv6};
        
        EndpointInfo(Type type, const std::string& ip) : type(type), ip(ip)
        {}
        
        EndpointInfo(const Iterator::value_type& val)
        {
            ip = val.endpoint().address().to_string();
            type = val.endpoint().address().is_v4() ? ipv4 : val.endpoint().address().is_v6() ? ipv6 : unknown;
        }
        
        bool operator ==(const EndpointInfo& other) const
        {
            return strncmp(other.ip.c_str(), ip.c_str(), std::min(other.ip.size(), ip.size())) == 0 && other.type == type;
        }
        
        bool operator !=(const EndpointInfo& other) const
        {
            return !operator==(other);
        }
        
        
        
        Type type;
        std::string ip;
    };

    
    Iterator createTestEndpoints(const std::vector<EndpointInfo> &endpointsInfo, const std::string& host, int port)
    {
        boost::asio::detail::addrinfo_type head;
        std::memset(&head, 0, sizeof(head));
        
        boost::asio::detail::addrinfo_type tail;
        std::memset(&tail, 0, sizeof(tail));
        
        tail.ai_next = &head;
        
        
        for (auto endpointInfo : endpointsInfo)
        {
            boost::asio::detail::addrinfo_type * addr = new addrinfo_type();
            std::memset(addr, 0, sizeof(*addr));
            
            tail.ai_next->ai_next = addr;
            tail.ai_next = addr;
            addr->ai_next = nullptr;
            
            addr->ai_family = endpointInfo.type == EndpointInfo::ipv4 ? AF_INET : AF_INET6;
            addr->ai_socktype = SOCK_STREAM;
            addr->ai_protocol = 0;
            addr->ai_flags = 0;
            
            if (addr->ai_family == AF_INET)
            {
                size_t sockaddr_size = sizeof(sockaddr_in);
                sockaddr_in* saddr = (sockaddr_in*)new unsigned char [sockaddr_size];
            
                addr->ai_addr = (sockaddr*)saddr;
                addr->ai_addrlen = sockaddr_size;
                addr->ai_addr->sa_family = addr->ai_family;
            
                saddr->sin_family = addr->ai_family;
                saddr->sin_port = port;
                saddr->sin_len = sockaddr_size;
            
                inet_pton(addr->ai_family, endpointInfo.ip.c_str(), &saddr->sin_addr);
            }
            else if (addr->ai_family == AF_INET6)
            {
                size_t sockaddr_size = sizeof(sockaddr_in6);
                sockaddr_in6* saddr = (sockaddr_in6*)new unsigned char [sockaddr_size];
                
                addr->ai_addr = (sockaddr*)saddr;
                addr->ai_addrlen = sockaddr_size;
                addr->ai_addr->sa_family = addr->ai_family;
                
                saddr->sin6_family = addr->ai_family;
                saddr->sin6_port = port;
                saddr->sin6_len = sockaddr_size;
                
                inet_pton(addr->ai_family, endpointInfo.ip.c_str(), &saddr->sin6_addr);
            }
        }
        
        std::stringstream ss;
        
        ss << port;
        
        auto returnValue = Iterator::create(head.ai_next, host, ss.str());
        
        
        for (auto next = head.ai_next; next != nullptr;)
        {
            auto ai_next = next->ai_next;
            delete [] next->ai_addr;
            delete next;
            
            next = ai_next;
        }
        
        return returnValue;
    }
    
    bool isEqual(Iterator endpoint, const std::vector<EndpointInfo> endpointInfo)
    {
        using Endpoints = std::vector<Iterator::value_type>;
        
        Endpoints endpoints;
        
        for(auto itr = endpoint; itr != Iterator(); ++itr)
        {
            endpoints.emplace_back(*itr);
        }
        
        if (endpoints.size() != endpointInfo.size())
        {
            return false;
        }
        
        for (int a = 0; a < endpoints.size(); ++a)
        {
            if (endpointInfo[a] != endpoints[a])
            {
                return false;
            }
        }
        
        return true;
    }
    
    struct TestCase
    {
        std::string description;
        struct
        {
            std::vector<EndpointInfo> endpointsInfo;
            std::string host;
            unsigned short port;
        } input;
        
        struct
        {
            std::vector<EndpointInfo> endpointsInfo;
            std::string host;
            unsigned short port;
        } expected;
    };
    
    std::vector<TestCase> testCases
    {
        {
            "No endpoints",
            {
                {},
                "myhost",
                8080
            },
            {
                {},
                "myhost",
                8080
            }
        },
        {
            "Single ipv4 endpoint",
            {
                {{EndpointInfo::ipv4, "127.0.0.1"}},
                "myhost",
                8080
            },
            {
                {{EndpointInfo::ipv4, "127.0.0.1"}},
                "myhost",
                8080
            }
        },
        {
            "Single ipv6 endpoint",
            {
                {{EndpointInfo::ipv6, "2001:db8:a0b:12f0::1"}},
                "myhost",
                8080
            },
            {
                {{EndpointInfo::ipv6, "2001:db8:a0b:12f0::1"}},
                "myhost",
                8080
            }
        },
        {
            "Multiple ipv4 endpoints",
            {
                {{EndpointInfo::ipv4, "127.0.0.1"}, {EndpointInfo::ipv4, "127.0.0.2"}, {EndpointInfo::ipv4, "127.0.0.3"}, {EndpointInfo::ipv4, "127.0.0.4"}, {EndpointInfo::ipv4, "127.0.0.5"}},
                "myhost",
                8080
            },
            {
                {{EndpointInfo::ipv4, "127.0.0.1"}, {EndpointInfo::ipv4, "127.0.0.2"}, {EndpointInfo::ipv4, "127.0.0.3"}, {EndpointInfo::ipv4, "127.0.0.4"}, {EndpointInfo::ipv4, "127.0.0.5"}},
                "myhost",
                8080
            }
        },
        {
            "Multiple ipv6 endpoints",
            {
                {{EndpointInfo::ipv6, "2001:db8:a0b:12f0::1"}, {EndpointInfo::ipv6, "2001:db8:a0b:12f1::1"}, {EndpointInfo::ipv6, "2001:db8:a0b:12f2::1"}, {EndpointInfo::ipv6, "2001:db8:a0b:12f3::1"}},
                "myhost",
                8080
            },
            {
                {{EndpointInfo::ipv6, "2001:db8:a0b:12f0::1"}, {EndpointInfo::ipv6, "2001:db8:a0b:12f1::1"}, {EndpointInfo::ipv6, "2001:db8:a0b:12f2::1"}, {EndpointInfo::ipv6, "2001:db8:a0b:12f3::1"}},
                "myhost",
                8080
            }
        },
        {
            "Single ipv6 endpoint followed by ipv4 endpoints",
            {
                {{EndpointInfo::ipv6, "2001:db8:a0b:12f0::1"}, {EndpointInfo::ipv4, "127.0.0.2"}, {EndpointInfo::ipv4, "127.0.0.3"}, {EndpointInfo::ipv4, "127.0.0.4"}, {EndpointInfo::ipv4, "127.0.0.5"}},
                "myhost",
                8080
            },
            {
                {{EndpointInfo::ipv6, "2001:db8:a0b:12f0::1"}, {EndpointInfo::ipv4, "127.0.0.2"}, {EndpointInfo::ipv4, "127.0.0.3"}, {EndpointInfo::ipv4, "127.0.0.4"}, {EndpointInfo::ipv4, "127.0.0.5"}},
                "myhost",
                8080
            }
        },
        {
            "Multiple ipv6 endpoint followed by ipv4 endpoints",
            {
                {{EndpointInfo::ipv6, "2001:db8:a0b:12f0::1"}, {EndpointInfo::ipv6, "2001:db8:a0b:12f1::1"}, {EndpointInfo::ipv6, "2001:db8:a0b:12f2::1"}, {EndpointInfo::ipv4, "127.0.0.2"}, {EndpointInfo::ipv4, "127.0.0.3"}, {EndpointInfo::ipv4, "127.0.0.4"}, {EndpointInfo::ipv4, "127.0.0.5"}},
                "myhost",
                8080
            },
            {
                {{EndpointInfo::ipv6, "2001:db8:a0b:12f0::1"}, {EndpointInfo::ipv4, "127.0.0.2"}, {EndpointInfo::ipv4, "127.0.0.3"}, {EndpointInfo::ipv4, "127.0.0.4"}, {EndpointInfo::ipv4, "127.0.0.5"}, {EndpointInfo::ipv6, "2001:db8:a0b:12f1::1"}, {EndpointInfo::ipv6, "2001:db8:a0b:12f2::1"}},
                "myhost",
                8080
            }
        },
        {
            "Single ipv4 endpoint followed by ipv6 endpoints",
            {
                {{EndpointInfo::ipv4, "127.0.0.2"}, {EndpointInfo::ipv6, "2001:db8:a0b:12f0::1"}, {EndpointInfo::ipv6, "2001:db8:a0b:12f1::1"}, {EndpointInfo::ipv6, "2001:db8:a0b:12f2::1"}},
                "myhost",
                8080
            },
            {
                {{EndpointInfo::ipv4, "127.0.0.2"}, {EndpointInfo::ipv6, "2001:db8:a0b:12f0::1"}, {EndpointInfo::ipv6, "2001:db8:a0b:12f1::1"}, {EndpointInfo::ipv6, "2001:db8:a0b:12f2::1"}},
                "myhost",
                8080
            }
        },
        {
            "Multiple ipv4 endpoint followed by ipv6 endpoints",
            {
                {{EndpointInfo::ipv4, "127.0.0.2"}, {EndpointInfo::ipv4, "127.0.0.3"}, {EndpointInfo::ipv4, "127.0.0.4"}, {EndpointInfo::ipv4, "127.0.0.5"}, {EndpointInfo::ipv6, "2001:db8:a0b:12f0::1"}, {EndpointInfo::ipv6, "2001:db8:a0b:12f1::1"}, {EndpointInfo::ipv6, "2001:db8:a0b:12f2::1"}},
                "myhost",
                8080
            },
            {
                {{EndpointInfo::ipv4, "127.0.0.2"}, {EndpointInfo::ipv4, "127.0.0.3"}, {EndpointInfo::ipv4, "127.0.0.4"}, {EndpointInfo::ipv4, "127.0.0.5"}, {EndpointInfo::ipv6, "2001:db8:a0b:12f0::1"}, {EndpointInfo::ipv6, "2001:db8:a0b:12f1::1"}, {EndpointInfo::ipv6, "2001:db8:a0b:12f2::1"}},
                "myhost",
                8080
            }
        },
    };
    
    
    SUITE(fast_ipv4_fallback_tests)
    {
        TEST(arrangeEndpoints_only_ipv4_endpoints)
        {
            for (auto & testCase : testCases)
            {
                auto itr = createTestEndpoints(testCase.input.endpointsInfo, testCase.input.host, testCase.input.port);
                auto endpoints = web::http::details::createHappyEyeballsEndpointList(itr);
                VERIFY_IS_TRUE(isEqual(endpoints, testCase.expected.endpointsInfo));
            }
        }
    }
}
}
}
}

#endif
