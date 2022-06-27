// The MIT License (MIT)
//
// Copyright (c) 2020 - 2022 Oleh Kulykov <olehkulykov@gmail.com>
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


#include <string>

#include "validator_exception.hpp"

#include <string.h>
#include <memory.h>

namespace validator {

    Exception::Exception(Exception && exception) noexcept : std::exception(),
        _what(exception._what),
        _code(exception._code),
        _line(exception._line) {
            exception._what = nullptr;
    }

    Exception::Exception(const ExceptionCode code, const int line, const char * what) noexcept : std::exception(),
        _code(code),
        _line(line) {
            const size_t len = what ? strlen(what) : 0;
            if (len && (_what = static_cast<char *>(malloc(len + 1)))) {
                memcpy(_what, what, len);
                _what[len] = 0;
            }
    }

    Exception::~Exception() noexcept {
        if (_what) {
            free(_what);
        }
    }

} // validator
