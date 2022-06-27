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


#include <cstddef>
#include <exception>

#ifndef __VALIDATOR_EXCEPTION_HPP__
#define __VALIDATOR_EXCEPTION_HPP__ 1

namespace validator {

    enum ExceptionCode {
        ExceptionCodeInternal           = 1,
        ExceptionCodeInput              = 2,
        ExceptionCodeFormat             = 3,
        ExceptionCodeValidation         = 4
    };
    
    class Exception final: std::exception {
    private:
        char * _what = nullptr;
        ExceptionCode _code;
        int _line;
        
        Exception & operator = (const Exception &) = delete;
        Exception & operator = (Exception &&) noexcept = delete;
        Exception(const Exception &) = delete;
        Exception() = delete;
        
    public:
        ExceptionCode code() const noexcept { return _code; }
        int line() const noexcept { return _line; }
        virtual const char * what() const noexcept { return _what; }
        Exception(Exception && exception) noexcept;
        Exception(const ExceptionCode code = ExceptionCodeInternal, const int line = 0, const char * what = nullptr) noexcept;
        ~Exception() noexcept;
    };

} // validator

#endif // !__VALIDATOR_EXCEPTION_HPP__
