//
// By using this Software, you are accepting original [LZMA SDK] and MIT license below:
//
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
#include <memory>
#include <string>
#include <sstream>
#include <iostream>
#include <fstream>
#include <exception>
#include <chrono>
#include <ctime>
#include <node.h>
#include <node_object_wrap.h>
#include <uv.h>
#include <openssl/pkcs7.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>

#include "file__appleincrootcertificate_cer.h"

namespace appleBase64 {
#include "apple_base64.h"

} // appleBase64

using namespace v8;

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
        
    public:
        ExceptionCode code() const noexcept { return _code; }
        int line() const noexcept { return _line; }
        virtual const char * what() const noexcept { return _what; }
        Exception(const ExceptionCode code = ExceptionCodeInternal, const int line = 0, const char * what = nullptr) noexcept;
        ~Exception() noexcept {
            if (_what) {
                free(_what);
            }
        }
    };

    Exception::Exception(const ExceptionCode code, const int line, const char * what) noexcept : std::exception(),
        _code(code),
        _line(line) {
            const size_t len = what ? strlen(what) : 0;
            if (len && (_what = static_cast<char *>(malloc(len + 1)))) {
                strncpy(_what, what, len);
            }
    }

    template<typename T>
    inline Local<Value> exceptionToError(Isolate * isolate, const T & exception);
    
    template<>
    inline Local<Value> exceptionToError(Isolate * isolate, const Exception & exception) {
        Local<Context> context = isolate->GetCurrentContext();
        auto error = v8::Exception::Error(String::NewFromUtf8(isolate, exception.what() ?: "unknown").ToLocalChecked());
        Local<Object> errorObject = error->ToObject(context).ToLocalChecked();
        errorObject->Set(context, String::NewFromUtf8(isolate, "lineNumber").ToLocalChecked(), Integer::New(isolate, exception.line())).Check();
        errorObject->Set(context, String::NewFromUtf8(isolate, "code").ToLocalChecked(), Integer::New(isolate, exception.code())).Check();
        return errorObject;
    }
    
    template<>
    inline Local<Value> exceptionToError(Isolate * isolate, const std::exception & exception) {
        return v8::Exception::Error(String::NewFromUtf8(isolate, exception.what() ?: "unknown").ToLocalChecked());
    }

} // validator

#define TRY \
try { \


#define CATCH_RET(ISOLATE) \
} catch (const validator::Exception & e) { \
    ISOLATE->ThrowException(validator::exceptionToError(ISOLATE, e)); return; \
} catch (const std::exception & e) { \
    ISOLATE->ThrowException(validator::exceptionToError(ISOLATE, e)); return; \
} \

namespace validator {

    enum GUIDValidationField  {
        GUIDValidationFieldBundleId     = 1 << 0,
        GUIDValidationFieldOpaqueValue  = 1 << 1,
        GUIDValidationFieldSHA1         = 1 << 2,
        GUIDValidationFieldAll          = (GUIDValidationFieldBundleId | GUIDValidationFieldOpaqueValue | GUIDValidationFieldSHA1)
    };

    struct BIODeleter final {
        void operator()(BIO * b) const {
            if (b) {
                BIO_free(b);
            }
        };
    };

    struct X509_STOREDeleter final {
        void operator()(X509_STORE * s) const {
            if (s) {
                X509_STORE_free(s);
            }
        };
    };

    struct PKCS7Deleter final {
        void operator()(PKCS7 * p) const {
            if (p) {
                PKCS7_free(p);
            }
        };
    };

    struct X509Deleter final {
        void operator()(X509 * x) const {
            if (x) {
                X509_free(x);
            }
        };
    };

    struct ASN1IntDeleter final {
        void operator()(ASN1_INTEGER * i) const {
            if (i) {
                ASN1_INTEGER_free(i);
            }
        };
    };

    template<typename T>
    T max(const T a, const T b) {
        return (a > b) ? (a) : (b);
    }

    class Validator final: public node::ObjectWrap {
    private:
        std::string _version;
        std::string _bundleIdentifier;
        std::vector<uint8_t> _GUID;
        std::vector<uint8_t> _rootCertificate;
        struct {
            const uint8_t * _bundleIdentifier = nullptr;
            const uint8_t * _opaqueValueV2 = nullptr;
            const uint8_t * _SHA1Hash = nullptr;
            long _opaqueValueSizeV2 = 0;
            long _SHA1HashSize = 0;
            long _bundleIdentifierSize = 0;
        } _asn1ReceiptFields;
        
        std::unique_ptr<BIO, BIODeleter> receiptPayload(std::vector<uint8_t> && receipts);
        void validateInAppReceiptPayload(const unsigned char * payload, const size_t payloadLen, Isolate * isolate, Local<Object> receiptObject);
        
    public:
        void setVersion(std::string && version) noexcept {
            _version = std::move(version);
        }
        
        void setBundleIdentifier(std::string && bundleIdentifier) noexcept {
            _bundleIdentifier = std::move(bundleIdentifier);
        }
        
        void setGUID(std::vector<uint8_t> && GUID) noexcept {
            _GUID = std::move(GUID);
        }
        
        void setRootCertificate(std::vector<uint8_t> && rootCertificate) noexcept {
            _rootCertificate = std::move(rootCertificate);
        }
        
        void validate(std::vector<uint8_t> && inReceipts, Isolate * isolate, Local<Object> receiptObject);
        
        template<typename T>
        static std::vector<T> fromApplesBase64(const char * base64String) {
            using namespace appleBase64;
            
            const auto theoreticalLength = Base64decode_len(base64String);
            if (theoreticalLength > INT_MAX) throw Exception(ExceptionCodeInput, __LINE__, "Base64 is too big");
            std::vector<T> res(theoreticalLength);
            const auto decodedLen = Base64decode(reinterpret_cast<char *>(res.data()), base64String);
            if (theoreticalLength != decodedLen) {
                res.resize(decodedLen);
            }
            return res;
        }
        
        static void RootCertificate(Local<String> property, const PropertyCallbackInfo<Value> & info);
        static void SetRootCertificate(Local<String> property, Local<Value> value, const PropertyCallbackInfo<void> & info);
        static void GUID(Local<String> property, const PropertyCallbackInfo<Value> & info);
        static void SetGUID(Local<String> property, Local<Value> value, const PropertyCallbackInfo<void> & info);
        static void Version(Local<String> property, const PropertyCallbackInfo<Value> & info);
        static void SetVersion(Local<String> property, Local<Value> value, const PropertyCallbackInfo<void> & info);
        static void BundleIdentifier(Local<String> property, const PropertyCallbackInfo<Value> & info);
        static void SetBundleIdentifier(Local<String> property, Local<Value> value, const PropertyCallbackInfo<void> & info);
        static void Validate(const FunctionCallbackInfo<Value> & args);
        static void Init(Local<Object> exports);
        static void New(const FunctionCallbackInfo<Value> & args);
    };
    
    std::unique_ptr<BIO, BIODeleter> Validator::receiptPayload(std::vector<uint8_t> && receipts) {
        const auto data = std::move(receipts);
        
        std::unique_ptr<BIO, BIODeleter> bP7(BIO_new_mem_buf(data.data(), static_cast<int>(data.size())), BIODeleter());
        if (!bP7) throw Exception(ExceptionCodeInternal, __LINE__, "PKCS7 container");
        
        BIO * bioPtr;
        if (_rootCertificate.size()) {
            bioPtr = BIO_new_mem_buf(_rootCertificate.data(), static_cast<int>(_rootCertificate.size()));
        } else {
            bioPtr = BIO_new_mem_buf(FILE__appleincrootcertificate_cer_PTR, static_cast<int>(FILE__appleincrootcertificate_cer_SIZE));
        }
        std::unique_ptr<BIO, BIODeleter> bx509(bioPtr, BIODeleter());
        if (!bx509) throw Exception(ExceptionCodeInternal, __LINE__, "X509 Apple Inc Root Certificate");
        
        std::unique_ptr<X509_STORE, X509_STOREDeleter> store(X509_STORE_new(), X509_STOREDeleter());
        if (!store) throw Exception(ExceptionCodeInternal, __LINE__, "X509 store");
        
        std::unique_ptr<BIO, BIODeleter> bOut(BIO_new(BIO_s_mem()), BIODeleter());
        if (!bOut) throw Exception(ExceptionCodeInternal, __LINE__, "Payload data");
        
        std::unique_ptr<PKCS7, PKCS7Deleter> p7(d2i_PKCS7_bio(bP7.get(), nullptr), PKCS7Deleter());
        if (!p7) throw Exception(ExceptionCodeInternal, __LINE__, "PKCS7 from data");
        
        std::unique_ptr<X509, X509Deleter> apple(d2i_X509_bio(bx509.get(), nullptr), X509Deleter());
        if (!apple) Exception(ExceptionCodeInternal, __LINE__, "X509 from certificate data");
        
        X509_STORE_add_cert(store.get(), apple.get());
        if (PKCS7_verify(p7.get(), nullptr, store.get(), nullptr, bOut.get(), 0) != 1) throw Exception(ExceptionCodeValidation, __LINE__, "PKCS7 verify/certificate");
        
        return bOut;
    }
    
    void Validator::validateInAppReceiptPayload(const unsigned char * payload, const size_t payloadLen, Isolate * isolate, Local<Object> receiptObject) {
        HandleScope handleScope(isolate);
        auto context = isolate->GetCurrentContext();
        const unsigned char * ptr = payload, * end = ptr + payloadLen;
        long len;
        int type, cls;
        
        ASN1_get_object(&ptr, &len, &type, &cls, end - ptr);
        if (type != V_ASN1_SET) throw Exception(ExceptionCodeFormat, __LINE__);
        
        std::unique_ptr<ASN1_INTEGER, ASN1IntDeleter> uniqReusableInt(ASN1_INTEGER_new(), ASN1IntDeleter());
        ASN1_INTEGER * reusableInt = uniqReusableInt.get(), * tmpInt;
        if (!reusableInt) throw Exception(ExceptionCodeInternal, __LINE__);

        while (ptr < end) {
            ASN1_get_object(&ptr, &len, &type, &cls, end - ptr);
            if (type != V_ASN1_SEQUENCE) throw Exception(ExceptionCodeFormat, __LINE__);
            
            const auto * sequenceEnd = ptr + len;
            
            if ((tmpInt = d2i_ASN1_INTEGER(&reusableInt, &ptr, sequenceEnd - ptr)) != reusableInt) throw Exception(tmpInt ? ExceptionCodeInternal : ExceptionCodeFormat, __LINE__);
            const auto attrType = ASN1_INTEGER_get(tmpInt);
            
            if ((tmpInt = d2i_ASN1_INTEGER(&reusableInt, &ptr, sequenceEnd - ptr)) != reusableInt) throw Exception(tmpInt ? ExceptionCodeInternal : ExceptionCodeFormat, __LINE__);
            if (ASN1_INTEGER_get(tmpInt) != 1) throw Exception(ExceptionCodeFormat, __LINE__); // unsupported attribute version -> check docs -> update code
            
            ASN1_get_object(&ptr, &len, &type, &cls, sequenceEnd - ptr);
            if (type != V_ASN1_OCTET_STRING) throw Exception(ExceptionCodeFormat, __LINE__);
            
            ASN1_UTF8STRING * tmpUtf8;
            ASN1_IA5STRING * tmpIA5;
            
            switch (attrType) {
                case 1701: // Quantity, INTEGER, 'quantity'
                    if ((tmpInt = d2i_ASN1_INTEGER(&reusableInt, &ptr, sequenceEnd - ptr)) == reusableInt) {
                        receiptObject->DefineOwnProperty(context, String::NewFromUtf8(isolate, "quantity").ToLocalChecked(), Number::New(isolate, ASN1_INTEGER_get(tmpInt)), None).Check();
                    } else { throw Exception(tmpInt ? ExceptionCodeInternal : ExceptionCodeFormat, __LINE__, "Quantity"); }
                    break;
                    
                case 1711: // Web Order Line Item ID, INTEGER, 'web_order_line_item_id'
                    if ((tmpInt = d2i_ASN1_INTEGER(&reusableInt, &ptr, sequenceEnd - ptr)) == reusableInt) {
                        receiptObject->DefineOwnProperty(context, String::NewFromUtf8(isolate, "web_order_line_item_id").ToLocalChecked(), Number::New(isolate, ASN1_INTEGER_get(tmpInt)), None).Check();
                    } else { throw Exception(tmpInt ? ExceptionCodeInternal : ExceptionCodeFormat, __LINE__, "Web Order Line Item ID"); }
                    break;
                    
                case 1719: // Subscription Introductory Price Period, INTEGER, 'is_in_intro_offer_period'
                    if ((tmpInt = d2i_ASN1_INTEGER(&reusableInt, &ptr, sequenceEnd - ptr)) == reusableInt) {
                        receiptObject->DefineOwnProperty(context, String::NewFromUtf8(isolate, "is_in_intro_offer_period").ToLocalChecked(), Number::New(isolate, ASN1_INTEGER_get(tmpInt)), None).Check();
                    } else { throw Exception(tmpInt ? ExceptionCodeInternal : ExceptionCodeFormat, __LINE__, "Subscription Introductory Price Period"); }
                    break;
                    
                case 1702: // Product Identifier, UTF8STRING, 'product_id'
                    if ((tmpUtf8 = d2i_ASN1_UTF8STRING(nullptr, &ptr, sequenceEnd - ptr))) {
                        receiptObject->DefineOwnProperty(context, String::NewFromUtf8(isolate, "product_id").ToLocalChecked(), String::NewFromUtf8(isolate, reinterpret_cast<const char *>(tmpUtf8->data), NewStringType::kNormal, static_cast<int>(tmpUtf8->length)).ToLocalChecked(), None).Check();
                        ASN1_UTF8STRING_free(tmpUtf8);
                    } else { throw Exception(ExceptionCodeFormat, __LINE__, "Product Identifier"); }
                    break;
                    
                case 1703: // Transaction Identifier, UTF8STRING, 'transaction_id'
                    if ((tmpUtf8 = d2i_ASN1_UTF8STRING(nullptr, &ptr, sequenceEnd - ptr))) {
                        receiptObject->DefineOwnProperty(context, String::NewFromUtf8(isolate, "transaction_id").ToLocalChecked(), String::NewFromUtf8(isolate, reinterpret_cast<const char *>(tmpUtf8->data), NewStringType::kNormal, static_cast<int>(tmpUtf8->length)).ToLocalChecked(), None).Check();
                        ASN1_UTF8STRING_free(tmpUtf8);
                    } else { throw Exception(ExceptionCodeFormat, __LINE__, "Transaction Identifier"); }
                    break;
                    
                case 1705: // Original Transaction Identifier, UTF8STRING, 'original_transaction_id'
                    if ((tmpUtf8 = d2i_ASN1_UTF8STRING(nullptr, &ptr, sequenceEnd - ptr))) {
                        receiptObject->DefineOwnProperty(context, String::NewFromUtf8(isolate, "original_transaction_id").ToLocalChecked(), String::NewFromUtf8(isolate, reinterpret_cast<const char *>(tmpUtf8->data), NewStringType::kNormal, static_cast<int>(tmpUtf8->length)).ToLocalChecked(), None).Check();
                        ASN1_UTF8STRING_free(tmpUtf8);
                    } else { throw Exception(ExceptionCodeFormat, __LINE__, "Original Transaction Identifier"); }
                    break;
                
                case 1704: // Purchase Date, IA5STRING, interpreted as an RFC 3339 date, 'purchase_date'
                    if ((tmpIA5 = d2i_ASN1_IA5STRING(nullptr, &ptr, sequenceEnd - ptr))) {
                        receiptObject->DefineOwnProperty(context, String::NewFromUtf8(isolate, "purchase_date").ToLocalChecked(), String::NewFromUtf8(isolate, reinterpret_cast<const char *>(tmpIA5->data), NewStringType::kNormal, static_cast<int>(tmpIA5->length)).ToLocalChecked(), None).Check();
                        ASN1_IA5STRING_free(tmpIA5);
                    } else { throw Exception(ExceptionCodeFormat, __LINE__, "Purchase Date"); }
                    break;
                    
                case 1706: { // Original Purchase Date, IA5STRING, interpreted as an RFC 3339 date, 'original_purchase_date'
                    if ((tmpIA5 = d2i_ASN1_IA5STRING(nullptr, &ptr, sequenceEnd - ptr))) {
                        receiptObject->DefineOwnProperty(context, String::NewFromUtf8(isolate, "original_purchase_date").ToLocalChecked(), String::NewFromUtf8(isolate, reinterpret_cast<const char *>(tmpIA5->data), NewStringType::kNormal, static_cast<int>(tmpIA5->length)).ToLocalChecked(), None).Check();
                        ASN1_IA5STRING_free(tmpIA5);
                    } else { throw Exception(ExceptionCodeFormat, __LINE__, "Original Purchase Date"); }
                } break;
                    
                case 1708: // Subscription Expiration Date, IA5STRING, interpreted as an RFC 3339 date, 'expires_date'
                    if ((tmpIA5 = d2i_ASN1_IA5STRING(nullptr, &ptr, sequenceEnd - ptr))) {
                        receiptObject->DefineOwnProperty(context, String::NewFromUtf8(isolate, "expires_date").ToLocalChecked(), String::NewFromUtf8(isolate, reinterpret_cast<const char *>(tmpIA5->data), NewStringType::kNormal, static_cast<int>(tmpIA5->length)).ToLocalChecked(), None).Check();
                        ASN1_IA5STRING_free(tmpIA5);
                    } else { throw Exception(ExceptionCodeFormat, __LINE__, "Subscription Expiration Date"); }
                    break;
                    
                case 1712: // Cancellation Date, IA5STRING, interpreted as an RFC 3339 date, 'cancellation_date'
                    if ((tmpIA5 = d2i_ASN1_IA5STRING(nullptr, &ptr, sequenceEnd - ptr))) {
                        receiptObject->DefineOwnProperty(context, String::NewFromUtf8(isolate, "cancellation_date").ToLocalChecked(), String::NewFromUtf8(isolate, reinterpret_cast<const char *>(tmpIA5->data), NewStringType::kNormal, static_cast<int>(tmpIA5->length)).ToLocalChecked(), None).Check();
                        ASN1_IA5STRING_free(tmpIA5);
                    } else { throw Exception(ExceptionCodeFormat, __LINE__, "Cancellation Date"); }
                    break;
                    
                default:
                    ptr += len;
                    break;
            }
        }
    }
    
    void Validator::validate(std::vector<uint8_t> && inReceipts, Isolate * isolate, Local<Object> receiptObject) {
        HandleScope handleScope(isolate);
        Local<Context> context = isolate->GetCurrentContext();
        auto payloadBio = receiptPayload(std::move(inReceipts));
        unsigned char * payload = nullptr;
        size_t payloadLen = BIO_get_mem_data(payloadBio.get(), &payload);
        
        const unsigned char * ptr = payload, * end = ptr + payloadLen;
        long len;
        int type, cls, guidFields = 0;
        
        ASN1_get_object(&ptr, &len, &type, &cls, end - ptr);
        if (type != V_ASN1_SET) throw Exception(ExceptionCodeFormat, __LINE__);
        
        std::unique_ptr<ASN1_INTEGER, ASN1IntDeleter> uniqReusableInt(ASN1_INTEGER_new(), ASN1IntDeleter());
        ASN1_INTEGER * reusableInt = uniqReusableInt.get(), * tmpInt;
        if (!reusableInt) throw Exception(ExceptionCodeInternal, __LINE__);
        
        auto receiptsArray = Array::New(isolate);
        uint32_t receiptsArrayIndex = 0;
        
        bool validateBundleIdentifier = _bundleIdentifier.length() > 0,
        validateGUID = _GUID.size() > 0,
        validateVersion = _version.length() > 0;
        
        while (ptr < end) {
            ASN1_get_object(&ptr, &len, &type, &cls, end - ptr);
            if (type != V_ASN1_SEQUENCE) throw Exception(ExceptionCodeFormat, __LINE__);
            
            const unsigned char * sequenceEnd = ptr + len;
            
            if ((tmpInt = d2i_ASN1_INTEGER(&reusableInt, &ptr, sequenceEnd - ptr)) != reusableInt) throw Exception(tmpInt ? ExceptionCodeInternal : ExceptionCodeFormat, __LINE__);
            const auto attrType = ASN1_INTEGER_get(tmpInt);
            
            if ((tmpInt = d2i_ASN1_INTEGER(&reusableInt, &ptr, sequenceEnd - ptr)) != reusableInt) throw Exception(tmpInt ? ExceptionCodeInternal : ExceptionCodeFormat, __LINE__);
            const long attrVersion = ASN1_INTEGER_get(tmpInt);
            
            ASN1_get_object(&ptr, &len, &type, &cls, sequenceEnd - ptr);
            if (type != V_ASN1_OCTET_STRING) throw Exception(ExceptionCodeFormat, __LINE__);
            const unsigned char * octStr = ptr;
            const long octStrLen = len;
            
            switch (attrType) {
                case 2: // Bundle Identifier, UTF8STRING, 'bundle_id'
                    if (attrVersion == 1) {
                        const unsigned char * tmpP = ptr;
                        ASN1_UTF8STRING * tmpUtf8 = d2i_ASN1_UTF8STRING(nullptr, &tmpP, len);
                        if (!tmpUtf8) throw Exception(ExceptionCodeFormat, __LINE__, "Bundle Identifier");
                        if (validateBundleIdentifier) {
                            validateBundleIdentifier = false;
                            const int res = (tmpUtf8->data && tmpUtf8->length >= 0) ? strncmp(_bundleIdentifier.c_str(), reinterpret_cast<const char *>(tmpUtf8->data), max<size_t>(_bundleIdentifier.length(), static_cast<size_t>(tmpUtf8->length))) : -1;
                            if (res != 0) { ASN1_UTF8STRING_free(tmpUtf8); throw Exception(ExceptionCodeValidation, __LINE__, "Bundle Identifier"); }
                        }
                        _asn1ReceiptFields._bundleIdentifier = ptr;
                        _asn1ReceiptFields._bundleIdentifierSize = len;
                        guidFields |= GUIDValidationFieldBundleId;
                        receiptObject->DefineOwnProperty(context, String::NewFromUtf8(isolate, "bundle_id").ToLocalChecked(), String::NewFromUtf8(isolate, reinterpret_cast<const char *>(tmpUtf8->data), NewStringType::kNormal, static_cast<int>(tmpUtf8->length)).ToLocalChecked(), None).Check();
                        ASN1_UTF8STRING_free(tmpUtf8);
                    } else {
                        throw Exception(ExceptionCodeFormat, __LINE__, "Bundle Identifier version"); // unsupported attribute version -> check docs -> update code
                    }
                    break;
                    
                case 4: // Opaque Value
                    if (attrVersion != 2) throw Exception(ExceptionCodeFormat, __LINE__, "Opaque Value version"); // unsupported attribute version -> check docs -> update code
                    _asn1ReceiptFields._opaqueValueV2 = ptr;
                    _asn1ReceiptFields._opaqueValueSizeV2 = len;
                    guidFields |= GUIDValidationFieldOpaqueValue;
                    break;
                    
                case 5: // SHA-1 Hash
                    if (attrVersion != 1) throw Exception(ExceptionCodeFormat, __LINE__, "SHA-1 Hash version"); // unsupported attribute version -> check docs -> update code
                    if (len != 20) throw Exception(ExceptionCodeFormat, __LINE__);
                    _asn1ReceiptFields._SHA1Hash = ptr;
                    _asn1ReceiptFields._SHA1HashSize = len;
                    guidFields |= GUIDValidationFieldSHA1;
                    break;
                    
                default:
                    break;
            }
            
            if (validateGUID && guidFields == GUIDValidationFieldAll) {
                validateGUID = false;
                if (!_asn1ReceiptFields._bundleIdentifier || !_asn1ReceiptFields._opaqueValueV2 || !_asn1ReceiptFields._SHA1Hash) throw Exception(ExceptionCodeValidation, __LINE__);
                EVP_MD_CTX * evp_ctx = EVP_MD_CTX_create();
                EVP_MD_CTX_init(evp_ctx);
                uint8_t digest[20] = { 0 };
                EVP_DigestInit_ex(evp_ctx, EVP_sha1(), nullptr);
                EVP_DigestUpdate(evp_ctx, _GUID.data(), _GUID.size()); // 1
                EVP_DigestUpdate(evp_ctx, _asn1ReceiptFields._opaqueValueV2, _asn1ReceiptFields._opaqueValueSizeV2); // 2
                EVP_DigestUpdate(evp_ctx, _asn1ReceiptFields._bundleIdentifier, _asn1ReceiptFields._bundleIdentifierSize); // 3
                EVP_DigestFinal_ex(evp_ctx, digest, nullptr);
                EVP_MD_CTX_destroy(evp_ctx);
                if (memcmp(digest, _asn1ReceiptFields._SHA1Hash, 20) != 0) throw Exception(ExceptionCodeValidation, __LINE__, "SHA-1 Hash");
            }
            
            switch (attrType) {
                case 3: // App Version, UTF8STRING, 'application_version'
                    if (attrVersion == 1) {
                        const unsigned char * tmpP = ptr;
                        ASN1_UTF8STRING * tmpUtf8 = d2i_ASN1_UTF8STRING(nullptr, &tmpP, len);
                        if (!tmpUtf8) throw Exception(ExceptionCodeFormat, __LINE__, "App Version");
                        if (validateVersion) {
                            validateVersion = false;
                            const int res = (tmpUtf8->data && tmpUtf8->length >= 0) ? strncmp(_version.c_str(), reinterpret_cast<const char *>(tmpUtf8->data), max<size_t>(_version.length(), static_cast<size_t>(tmpUtf8->length))) : -1;
                            if (res != 0) { ASN1_UTF8STRING_free(tmpUtf8); throw Exception(ExceptionCodeValidation, __LINE__, "App Version"); }
                        }
                        receiptObject->DefineOwnProperty(context, String::NewFromUtf8(isolate, "application_version").ToLocalChecked(), String::NewFromUtf8(isolate, reinterpret_cast<const char *>(tmpUtf8->data), NewStringType::kNormal, static_cast<int>(tmpUtf8->length)).ToLocalChecked(), None).Check();
                        ASN1_UTF8STRING_free(tmpUtf8);
                    } else {
                        throw Exception(ExceptionCodeFormat, __LINE__, "App Version version"); // unsupported attribute version -> check docs -> update code
                    }
                    break;
                    
                case 17: // In-App Purchase Receipt, 'in_app'
                    if (attrVersion == 1) {
                        auto inAppReceiptObject = Object::New(isolate);
                        validateInAppReceiptPayload(ptr, len, isolate, inAppReceiptObject);
                        receiptsArray->Set(context, receiptsArrayIndex++, inAppReceiptObject).Check();
                    } else {
                        throw Exception(ExceptionCodeFormat, __LINE__, "In-App Purchase Receipt version"); // unsupported attribute version -> check docs -> update code
                    }
                    break;
                    
                default:
                    break;
            }
            
            ptr = octStr + octStrLen;
        }

        receiptObject->DefineOwnProperty(context, String::NewFromUtf8(isolate, "in_app").ToLocalChecked(), receiptsArray, None).Check();
    }
    
    void Validator::New(const FunctionCallbackInfo<Value> & args) {
        Isolate * isolate = args.GetIsolate();
        HandleScope handleScope(isolate);
        auto context = isolate->GetCurrentContext();
        if (args.IsConstructCall()) {
            Validator * obj = nullptr;
            TRY
            obj = new Validator();
            CATCH_RET(isolate)
            obj->Wrap(args.This());
            args.GetReturnValue().Set(args.This());
        } else {
            auto constructor = args.Data().As<Object>()->GetInternalField(0).As<Function>();
            TryCatch trycatch(isolate);
            auto maybeResult = constructor->NewInstance(context, 0, nullptr);
            if (maybeResult.IsEmpty()) {
                if (trycatch.HasCaught()) {
                    trycatch.ReThrow();
                } else {
                    isolate->ThrowException(v8::Exception::Error(String::NewFromUtf8(isolate, "Can't instantiate Validator.").ToLocalChecked()));
                }
                return;
            }
            args.GetReturnValue().Set(maybeResult.ToLocalChecked());
        }
    }
    
    void Validator::Version(Local<String> property, const PropertyCallbackInfo<Value> & info) {
        Isolate * isolate = info.GetIsolate();
        HandleScope handleScope(isolate);
        TRY
        Validator * validator = ObjectWrap::Unwrap<Validator>(info.Holder());
        if (validator->_version.length() > 0) {
            info.GetReturnValue().Set(String::NewFromUtf8(isolate, validator->_version.c_str()).ToLocalChecked());
        } else {
            info.GetReturnValue().SetUndefined();
        }
        CATCH_RET(isolate)
    }

    void Validator::SetVersion(Local<String> property, Local<Value> value, const PropertyCallbackInfo<void> & info) {
        Isolate * isolate = info.GetIsolate();
        HandleScope handleScope(isolate);
        TRY
        Validator * validator = ObjectWrap::Unwrap<Validator>(info.Holder());
        validator->_version.clear();
        if (value->IsString()) {
            String::Utf8Value str(isolate, value);
            if (str.length() > 0) {
                validator->_version = *str;
            }
        }
        CATCH_RET(isolate)
    }

    void Validator::BundleIdentifier(Local<String> property, const PropertyCallbackInfo<Value> & info) {
        Isolate * isolate = info.GetIsolate();
        HandleScope handleScope(isolate);
        TRY
        Validator * validator = ObjectWrap::Unwrap<Validator>(info.Holder());
        if (validator->_bundleIdentifier.length() > 0) {
            info.GetReturnValue().Set(String::NewFromUtf8(isolate, validator->_bundleIdentifier.c_str()).ToLocalChecked());
        } else {
            info.GetReturnValue().SetUndefined();
        }
        CATCH_RET(isolate)
    }

    void Validator::SetBundleIdentifier(Local<String> property, Local<Value> value, const PropertyCallbackInfo<void> & info) {
        Isolate * isolate = info.GetIsolate();
        HandleScope handleScope(isolate);
        TRY
        Validator * validator = ObjectWrap::Unwrap<Validator>(info.Holder());
        validator->_bundleIdentifier.clear();
        if (value->IsString()) {
            String::Utf8Value str(isolate, value);
            if (str.length() > 0) {
                validator->_bundleIdentifier = *str;
            }
        }
        CATCH_RET(isolate)
    }

    void Validator::GUID(Local<String> property, const PropertyCallbackInfo<Value> & info) {
        Isolate * isolate = info.GetIsolate();
        HandleScope handleScope(isolate);
        Validator * validator = ObjectWrap::Unwrap<Validator>(info.Holder());
        TRY
        if (validator->_GUID.size() > 0) {
            auto backingStore = ArrayBuffer::NewBackingStore(isolate, validator->_GUID.size());
            if (!backingStore) throw Exception(ExceptionCodeInternal, __LINE__, "NewBackingStore");
            memcpy(backingStore->Data(), validator->_GUID.data(), validator->_GUID.size());
            info.GetReturnValue().Set(ArrayBuffer::New(isolate, std::move(backingStore)));
        } else {
            info.GetReturnValue().SetUndefined();
        }
        CATCH_RET(isolate)
    }

    void Validator::SetGUID(Local<String> property, Local<Value> value, const PropertyCallbackInfo<void> & info) {
        Isolate * isolate = info.GetIsolate();
        HandleScope handleScope(isolate);
        TRY
        Validator * validator = ObjectWrap::Unwrap<Validator>(info.Holder());
        validator->_GUID.clear();
        if (value->IsString()) {
            String::Utf8Value str(isolate, value);
            if (str.length() > 0) {
                validator->_GUID = Validator::fromApplesBase64<uint8_t>(*str);
            }
        } else if (value->IsArrayBuffer()) {
            auto arrayBuffer = Local<ArrayBuffer>::Cast(value);
            const auto backingStore = arrayBuffer->GetBackingStore();
            if (backingStore && backingStore->ByteLength() > 0) {
                std::vector<uint8_t> v;
                v.resize(backingStore->ByteLength());
                memcpy(v.data(), backingStore->Data(), backingStore->ByteLength());
                validator->_GUID = std::move(v);
            }
        }
        CATCH_RET(isolate)
    }

    void Validator::RootCertificate(Local<String> property, const PropertyCallbackInfo<Value> & info) {
        Isolate * isolate = info.GetIsolate();
        HandleScope handleScope(isolate);
        TRY
        Validator * validator = ObjectWrap::Unwrap<Validator>(info.Holder());
        if (validator->_rootCertificate.size() > 0) {
            auto backingStore = ArrayBuffer::NewBackingStore(isolate, validator->_rootCertificate.size());
            if (!backingStore) throw Exception(ExceptionCodeInternal, __LINE__, "NewBackingStore");
            memcpy(backingStore->Data(), validator->_rootCertificate.data(), validator->_rootCertificate.size());
            info.GetReturnValue().Set(ArrayBuffer::New(isolate, std::move(backingStore)));
        } else {
            auto backingStore = ArrayBuffer::NewBackingStore(isolate, FILE__appleincrootcertificate_cer_SIZE);
            if (!backingStore) throw Exception(ExceptionCodeInternal, __LINE__, "NewBackingStore");
            memcpy(backingStore->Data(), FILE__appleincrootcertificate_cer_PTR, FILE__appleincrootcertificate_cer_SIZE);
            info.GetReturnValue().Set(ArrayBuffer::New(isolate, std::move(backingStore)));
        }
        CATCH_RET(isolate)
    }

    void Validator::SetRootCertificate(Local<String> property, Local<Value> value, const PropertyCallbackInfo<void> & info) {
        Isolate * isolate = info.GetIsolate();
        HandleScope handleScope(isolate);
        TRY
        Validator * validator = ObjectWrap::Unwrap<Validator>(info.Holder());
        validator->_rootCertificate.clear();
        if (value->IsArrayBuffer()) {
            auto arrayBuffer = Local<ArrayBuffer>::Cast(value);
            const auto backingStore = arrayBuffer->GetBackingStore();
            if (backingStore && backingStore->ByteLength() > 0) {
                std::vector<uint8_t> v;
                v.resize(backingStore->ByteLength());
                memcpy(v.data(), backingStore->Data(), backingStore->ByteLength());
                validator->_rootCertificate = std::move(v);
            }
        }
        CATCH_RET(isolate)
    }

    void Validator::Validate(const FunctionCallbackInfo<Value> & args) {
        Isolate * isolate = args.GetIsolate();
        HandleScope handleScope(isolate);
        auto receiptObject = Object::New(isolate);
        TRY
        Validator * validator = ObjectWrap::Unwrap<Validator>(args.Holder());
        std::vector<uint8_t> inReceipt;
        if (args.Length() > 0) {
            if (args[0]->IsString()) {
                String::Utf8Value str(isolate, args[0]);
                if (str.length() > 0) {
                    inReceipt = Validator::fromApplesBase64<uint8_t>(*str);
                } else {
                    throw Exception(ExceptionCodeInput, __LINE__, "Input Base64 is empty");
                }
            } else if (args[0]->IsArrayBuffer()) {
                auto arrayBuffer = Local<ArrayBuffer>::Cast(args[0]);
                const auto backingStore = arrayBuffer->GetBackingStore();
                if (backingStore && backingStore->ByteLength() > 0) {
                    std::vector<uint8_t> v;
                    v.resize(backingStore->ByteLength());
                    memcpy(v.data(), backingStore->Data(), backingStore->ByteLength());
                    inReceipt = std::move(v);
                } else {
                    throw Exception(ExceptionCodeInput, __LINE__, "Input array buffer is empty");
                }
            }
        }
        if (inReceipt.size() > 0) {
            validator->validate(std::move(inReceipt), isolate, receiptObject);
        } else {
            throw Exception(ExceptionCodeInput, __LINE__, "No input");
        }
        CATCH_RET(isolate)
        args.GetReturnValue().Set(receiptObject);
    }

    void Validator::Init(Local<Object> exports) {
        Isolate * isolate = exports->GetIsolate();
        HandleScope handleScope(isolate);
        auto context = isolate->GetCurrentContext();
        auto dataTpl = ObjectTemplate::New(isolate);
        dataTpl->SetInternalFieldCount(1);
        auto dataObject = dataTpl->NewInstance(context).ToLocalChecked();
        
        // Constructor template: 'Validator' func tpl
        auto ctorTpl = FunctionTemplate::New(isolate, Validator::New, dataObject);
        ctorTpl->SetClassName(String::NewFromUtf8(isolate, "Validator").ToLocalChecked());
        
        auto ctorInstTpl = ctorTpl->InstanceTemplate();
        ctorInstTpl->SetInternalFieldCount(1);
        
        // (new Validator(...)).<func>(...)
        auto ctorProtoTpl = ctorTpl->PrototypeTemplate();
        ctorProtoTpl->Set(String::NewFromUtf8(isolate, "validate").ToLocalChecked(), FunctionTemplate::New(isolate, Validator::Validate), static_cast<PropertyAttribute>(ReadOnly | DontDelete));
        
        // (new Validator(...)).<prop>
        ctorInstTpl->SetAccessor(String::NewFromUtf8(isolate, "version").ToLocalChecked(), Validator::Version, Validator::SetVersion, Local<Value>(), DEFAULT, DontDelete);
        ctorInstTpl->SetAccessor(String::NewFromUtf8(isolate, "bundleIdentifier").ToLocalChecked(), Validator::BundleIdentifier, Validator::SetBundleIdentifier, Local<Value>(), DEFAULT, DontDelete);
        ctorInstTpl->SetAccessor(String::NewFromUtf8(isolate, "GUID").ToLocalChecked(), Validator::GUID, Validator::SetGUID, Local<Value>(), DEFAULT, DontDelete);
        ctorInstTpl->SetAccessor(String::NewFromUtf8(isolate, "rootCertificate").ToLocalChecked(), Validator::RootCertificate, Validator::SetRootCertificate, Local<Value>(), DEFAULT, DontDelete);
        
        auto constructor = ctorTpl->GetFunction(context).ToLocalChecked();
        dataObject->SetInternalField(0, constructor);
        exports->Set(context, String::NewFromUtf8(isolate, "Validator").ToLocalChecked(), constructor).FromJust();
    }
    
} // localValidator

static void ValidatorModuleInit(Local<Object> exports) {
    Isolate * isolate = exports->GetIsolate();
    HandleScope handleScope(isolate);
    auto context = isolate->GetCurrentContext();
    
    auto errorCodeObject = Object::New(isolate);
    errorCodeObject->DefineOwnProperty(context, String::NewFromUtf8(isolate, "internal").ToLocalChecked(), Uint32::NewFromUnsigned(isolate, validator::ExceptionCodeInternal), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).Check();
    errorCodeObject->DefineOwnProperty(context, String::NewFromUtf8(isolate, "input").ToLocalChecked(), Uint32::NewFromUnsigned(isolate, validator::ExceptionCodeInput), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).Check();
    errorCodeObject->DefineOwnProperty(context, String::NewFromUtf8(isolate, "format").ToLocalChecked(), Uint32::NewFromUnsigned(isolate, validator::ExceptionCodeFormat), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).Check();
    errorCodeObject->DefineOwnProperty(context, String::NewFromUtf8(isolate, "validation").ToLocalChecked(), Uint32::NewFromUnsigned(isolate, validator::ExceptionCodeValidation), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).Check();
    exports->Set(context, String::NewFromUtf8(isolate, "ErrorCode").ToLocalChecked(), errorCodeObject).FromJust();
    
    validator::Validator::Init(exports);
}

NODE_MODULE(aiap_local_validator, ValidatorModuleInit)

#include "file__appleincrootcertificate_cer.h"