// The MIT License (MIT)
//
// Copyright (c) 2020 Oleh Kulykov <olehkulykov@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//


#include <limits>
#include <limits.h>

#include "validator_base64.hpp"
#include "validator_exception.hpp"

#include "apple_base64.h"

namespace validator {

    std::vector<uint8_t> decodeBase64String(const char * base64String) {
        if (!base64String) return std::vector<uint8_t>();
        
        const auto theoreticalLength = Base64decode_len(base64String);
        if (theoreticalLength > INT_MAX) throw Exception(ExceptionCodeInput, __LINE__, "Base64 is too big");
        std::vector<uint8_t> res(theoreticalLength);
        const auto decodedLen = Base64decode(reinterpret_cast<char *>(res.data()), base64String);
        if (theoreticalLength != decodedLen) {
            res.resize(decodedLen);
        }
        return res;
    }

} // validator
