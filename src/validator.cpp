// The MIT License (MIT)
//
// Copyright (c) 2020 - 2021 Oleh Kulykov <olehkulykov@gmail.com>
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
#include <node.h>
#include <node_object_wrap.h>
#include <openssl/pkcs7.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>

#include "validator_exception.hpp"
#include "validator_date.hpp"
#include "validator_base64.hpp"
#include "validator_files.hpp"

#include <string.h>

using namespace v8;

#if !defined(NODE_MAJOR_VERSION)
#error "NODE_MAJOR_VERSION"
#endif


#define VALIDATOR_TRY \
try { \


#if (NODE_MAJOR_VERSION == 11 || NODE_MAJOR_VERSION == 10)

#define VALIDATOR_CREATEDATAPROPERTY_NUM(ISOLATE, CTX, OBJ, KEY, VAL) \
OBJ->CreateDataProperty(CTX, String::NewFromUtf8(ISOLATE, KEY), Number::New(ISOLATE, VAL)).ToChecked(); \


#define VALIDATOR_CREATEDATAPROPERTY_STR_LEN(ISOLATE, CTX, OBJ, KEY, VAL, VAL_LEN) \
OBJ->CreateDataProperty(CTX, String::NewFromUtf8(ISOLATE, KEY, NewStringType::kNormal).ToLocalChecked(), String::NewFromUtf8(ISOLATE, VAL, NewStringType::kNormal, VAL_LEN).ToLocalChecked()).ToChecked(); \


#define VALIDATOR_CREATEDATAPROPERTY_DATE_MS(ISOLATE, CTX, OBJ, KEY, MS) \
OBJ->CreateDataProperty(CTX, String::NewFromUtf8(ISOLATE, KEY, NewStringType::kNormal).ToLocalChecked(), Number::New(ISOLATE, MS)).ToChecked(); \


#define VALIDATOR_CREATEDATAPROPERTY_OBJ(ISOLATE, CTX, OBJ, KEY, VAL_OBJ) \
OBJ->CreateDataProperty(CTX, String::NewFromUtf8(isolate, KEY, NewStringType::kNormal).ToLocalChecked(), VAL_OBJ).ToChecked(); \


#define VALIDATOR_CATCH_RET(ISOLATE, CTX) \
} catch (const validator::Exception & e) { \
    auto error = v8::Exception::Error(String::NewFromUtf8(ISOLATE, e.what() ?: "unknown", NewStringType::kNormal).ToLocalChecked()); \
    auto errorObject = error->ToObject(CTX).ToLocalChecked(); \
    errorObject->Set(CTX, String::NewFromUtf8(ISOLATE, "lineNumber", NewStringType::kNormal).ToLocalChecked(), Integer::New(ISOLATE, e.line())).ToChecked(); \
    errorObject->Set(CTX, String::NewFromUtf8(ISOLATE, "code", NewStringType::kNormal).ToLocalChecked(), Integer::New(ISOLATE, e.code())).ToChecked(); \
    ISOLATE->ThrowException(errorObject); \
    return; \
} catch (const std::exception & e) { \
    ISOLATE->ThrowException(v8::Exception::Error(String::NewFromUtf8(ISOLATE, e.what() ?: "unknown", NewStringType::kNormal).ToLocalChecked())); \
    return; \
} \


#define VALIDATOR_THROWEXCEPTION(ISOLATE, STR) \
ISOLATE->ThrowException(v8::Exception::Error(String::NewFromUtf8(ISOLATE, STR, NewStringType::kNormal).ToLocalChecked())); \


#define VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(ISOLATE, STR) \
String::NewFromUtf8(ISOLATE, STR, NewStringType::kNormal).ToLocalChecked()


#elif (NODE_MAJOR_VERSION == 12)

#define VALIDATOR_CREATEDATAPROPERTY_NUM(ISOLATE, CTX, OBJ, KEY, VAL) \
OBJ->CreateDataProperty(CTX, String::NewFromUtf8(ISOLATE, KEY, NewStringType::kNormal).ToLocalChecked(), Number::New(ISOLATE, VAL)).Check(); \


#define VALIDATOR_CREATEDATAPROPERTY_STR_LEN(ISOLATE, CTX, OBJ, KEY, VAL, VAL_LEN) \
OBJ->CreateDataProperty(CTX, String::NewFromUtf8(ISOLATE, KEY, NewStringType::kNormal).ToLocalChecked(), String::NewFromUtf8(ISOLATE, VAL, NewStringType::kNormal, VAL_LEN).ToLocalChecked()).Check(); \


#define VALIDATOR_CREATEDATAPROPERTY_DATE_MS(ISOLATE, CTX, OBJ, KEY, MS) \
OBJ->CreateDataProperty(CTX, String::NewFromUtf8(ISOLATE, KEY, NewStringType::kNormal).ToLocalChecked(), Number::New(ISOLATE, MS)).Check(); \


#define VALIDATOR_CREATEDATAPROPERTY_OBJ(ISOLATE, CTX, OBJ, KEY, VAL_OBJ) \
OBJ->CreateDataProperty(CTX, String::NewFromUtf8(isolate, KEY, NewStringType::kNormal).ToLocalChecked(), VAL_OBJ).Check(); \


#define VALIDATOR_CATCH_RET(ISOLATE, CTX) \
} catch (const validator::Exception & e) { \
    auto error = v8::Exception::Error(String::NewFromUtf8(ISOLATE, e.what() ?: "unknown", NewStringType::kNormal).ToLocalChecked()); \
    auto errorObject = error->ToObject(CTX).ToLocalChecked(); \
    errorObject->Set(CTX, String::NewFromUtf8(ISOLATE, "lineNumber", NewStringType::kNormal).ToLocalChecked(), Integer::New(ISOLATE, e.line())).Check(); \
    errorObject->Set(CTX, String::NewFromUtf8(ISOLATE, "code", NewStringType::kNormal).ToLocalChecked(), Integer::New(ISOLATE, e.code())).Check(); \
    ISOLATE->ThrowException(errorObject); \
    return; \
} catch (const std::exception & e) { \
    ISOLATE->ThrowException(v8::Exception::Error(String::NewFromUtf8(ISOLATE, e.what() ?: "unknown", NewStringType::kNormal).ToLocalChecked())); \
    return; \
} \


#define VALIDATOR_THROWEXCEPTION(ISOLATE, STR) \
ISOLATE->ThrowException(v8::Exception::Error(String::NewFromUtf8(ISOLATE, STR, NewStringType::kNormal).ToLocalChecked())); \


#define VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(ISOLATE, STR) \
String::NewFromUtf8(ISOLATE, STR, NewStringType::kNormal).ToLocalChecked()


#else  // NODE_MAJOR_VERSION != 12

#define VALIDATOR_CREATEDATAPROPERTY_NUM(ISOLATE, CTX, OBJ, KEY, VAL) \
OBJ->CreateDataProperty(CTX, String::NewFromUtf8(ISOLATE, KEY).ToLocalChecked(), Number::New(ISOLATE, VAL)).Check(); \


#define VALIDATOR_CREATEDATAPROPERTY_STR_LEN(ISOLATE, CTX, OBJ, KEY, VAL, VAL_LEN) \
OBJ->CreateDataProperty(CTX, String::NewFromUtf8(ISOLATE, KEY).ToLocalChecked(), String::NewFromUtf8(ISOLATE, VAL, NewStringType::kNormal, VAL_LEN).ToLocalChecked()).Check(); \


#define VALIDATOR_CREATEDATAPROPERTY_DATE_MS(ISOLATE, CTX, OBJ, KEY, MS) \
OBJ->CreateDataProperty(CTX, String::NewFromUtf8(ISOLATE, KEY).ToLocalChecked(), Number::New(ISOLATE, MS)).Check(); \


#define VALIDATOR_CREATEDATAPROPERTY_OBJ(ISOLATE, CTX, OBJ, KEY, VAL_OBJ) \
OBJ->CreateDataProperty(CTX, String::NewFromUtf8(isolate, KEY).ToLocalChecked(), VAL_OBJ).Check(); \


#define VALIDATOR_CATCH_RET(ISOLATE, CTX) \
} catch (const validator::Exception & e) { \
    auto error = v8::Exception::Error(String::NewFromUtf8(ISOLATE, e.what() ?: "unknown").ToLocalChecked()); \
    auto errorObject = error->ToObject(CTX).ToLocalChecked(); \
    errorObject->Set(CTX, String::NewFromUtf8(ISOLATE, "lineNumber").ToLocalChecked(), Integer::New(ISOLATE, e.line())).Check(); \
    errorObject->Set(CTX, String::NewFromUtf8(ISOLATE, "code").ToLocalChecked(), Integer::New(ISOLATE, e.code())).Check(); \
    ISOLATE->ThrowException(errorObject); \
    return; \
} catch (const std::exception & e) { \
    ISOLATE->ThrowException(v8::Exception::Error(String::NewFromUtf8(ISOLATE, e.what() ?: "unknown").ToLocalChecked())); \
    return; \
} \


#define VALIDATOR_THROWEXCEPTION(ISOLATE, STR) \
ISOLATE->ThrowException(v8::Exception::Error(String::NewFromUtf8(ISOLATE, STR).ToLocalChecked())); \


#define VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(ISOLATE, STR) \
String::NewFromUtf8(ISOLATE, STR).ToLocalChecked()


#endif // NODE_MAJOR_VERSION != 12


namespace validator {

    enum GUIDValidationField: uint32_t {
        GUIDValidationFieldBundleId     = 1 << 0,
        GUIDValidationFieldOpaqueValue  = 1 << 1,
        GUIDValidationFieldSHA1         = 1 << 2,
        GUIDValidationFieldAll          = (GUIDValidationFieldBundleId |
                                           GUIDValidationFieldOpaqueValue |
                                           GUIDValidationFieldSHA1)
    };

    enum InAppReceiptField: uint32_t {
        InAppReceiptFieldQuantity               = 1 << 0,
        InAppReceiptFieldWebOrderLineItemId     = 1 << 1,
        InAppReceiptFieldIsInIntroOfferPeriod   = 1 << 2,
        InAppReceiptFieldProductId              = 1 << 3,
        InAppReceiptFieldTransactionId          = 1 << 4,
        InAppReceiptFieldOriginalTransactionId  = 1 << 5,
        InAppReceiptFieldPurchaseDate           = 1 << 6,
        InAppReceiptFieldOriginalPurchaseDate   = 1 << 7,
        InAppReceiptFieldExpiresDate            = 1 << 8,
        InAppReceiptFieldCancellationDate       = 1 << 9,
        InAppReceiptFieldAll                    = (InAppReceiptFieldQuantity |
                                                   InAppReceiptFieldWebOrderLineItemId |
                                                   InAppReceiptFieldIsInIntroOfferPeriod |
                                                   InAppReceiptFieldProductId |
                                                   InAppReceiptFieldTransactionId |
                                                   InAppReceiptFieldOriginalTransactionId |
                                                   InAppReceiptFieldPurchaseDate |
                                                   InAppReceiptFieldOriginalPurchaseDate |
                                                   InAppReceiptFieldExpiresDate |
                                                   InAppReceiptFieldCancellationDate)
    };
    
    struct BIODeleter final {
        void operator()(BIO * b) const {
            if (b) {
                BIO_free_all(b);
            }
        };
    };
    
    struct X509StoreDeleter final {
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
    
    struct ASN1Utf8StringDeleter final {
        void operator()(ASN1_UTF8STRING * s) const {
            if (s) {
                ASN1_UTF8STRING_free(s);
            }
        };
    };
    
    struct ASN1Ia5StringDeleter final {
        void operator()(ASN1_IA5STRING * s) const {
            if (s) {
                ASN1_IA5STRING_free(s);
            }
        };
    };

    struct ASN1ValidationReceiptFields final {
        const uint8_t * bundleIdentifier = nullptr;
        const uint8_t * opaqueValueV2 = nullptr;
        const uint8_t * SHA1Hash = nullptr;
        long opaqueValueV2Size = 0;
        long SHA1HashSize = 0;
        long bundleIdentifierSize = 0;
    };

    class Validator final: public node::ObjectWrap {
    private:
        std::string _version;
        std::string _bundleIdentifier;
        std::vector<uint8_t> _GUID;
        std::vector<uint8_t> _rootCertificate;
        uint32_t _inAppReceiptFields = InAppReceiptFieldAll;
        
        std::unique_ptr<BIO, BIODeleter> receiptPayload(std::vector<uint8_t> && receipts);
        void parseInAppReceiptPayload(const unsigned char * payload, const size_t payloadLen, Isolate * isolate, Local<Object> receiptObject);
        void validate(std::vector<uint8_t> && inReceipts, Isolate * isolate, Local<Object> receiptObject);
        
        Validator & operator = (const Validator &) = delete;
        Validator & operator = (Validator &&) noexcept = delete;
        Validator(const Validator &) = delete;
        Validator(Validator &&) noexcept = delete;
        Validator() : node::ObjectWrap() { }
        
        static void InAppReceiptFields(Local<String> property, const PropertyCallbackInfo<Value> & info);
        static void SetInAppReceiptFields(Local<String> property, Local<Value> value, const PropertyCallbackInfo<void> & info);
        static void RootCertificate(Local<String> property, const PropertyCallbackInfo<Value> & info);
        static void SetRootCertificate(Local<String> property, Local<Value> value, const PropertyCallbackInfo<void> & info);
        static void GUID(Local<String> property, const PropertyCallbackInfo<Value> & info);
        static void SetGUID(Local<String> property, Local<Value> value, const PropertyCallbackInfo<void> & info);
        static void Version(Local<String> property, const PropertyCallbackInfo<Value> & info);
        static void SetVersion(Local<String> property, Local<Value> value, const PropertyCallbackInfo<void> & info);
        static void BundleIdentifier(Local<String> property, const PropertyCallbackInfo<Value> & info);
        static void SetBundleIdentifier(Local<String> property, Local<Value> value, const PropertyCallbackInfo<void> & info);
        static void Validate(const FunctionCallbackInfo<Value> & args);
        static void New(const FunctionCallbackInfo<Value> & args);
        
    public:
        static void Init(Local<Object> exports);
    };
    
    std::unique_ptr<BIO, BIODeleter> Validator::receiptPayload(std::vector<uint8_t> && receipts) {
        const auto data = std::move(receipts);
        
        std::unique_ptr<BIO, BIODeleter> bP7(BIO_new_mem_buf(data.data(), static_cast<int>(data.size())), BIODeleter());
        if (!bP7) throw Exception(ExceptionCodeInternal, __LINE__, "PKCS7 container");
        
        BIO * bioPtr;
        std::pair<uint8_t *, size_t> bundledCertificate;
        if (_rootCertificate.size()) {
            bioPtr = BIO_new_mem_buf(_rootCertificate.data(), static_cast<int>(_rootCertificate.size()));
        } else {
            bundledCertificate = AppleIncRootCertificateFile();
            bioPtr = BIO_new_mem_buf(bundledCertificate.first, static_cast<int>(bundledCertificate.second));
        }
        std::unique_ptr<BIO, BIODeleter> bx509(bioPtr, BIODeleter());
        if (!bx509) throw Exception(ExceptionCodeInternal, __LINE__, "X509 Apple Inc Root Certificate");
        
        std::unique_ptr<X509_STORE, X509StoreDeleter> store(X509_STORE_new(), X509StoreDeleter());
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
    
    void Validator::parseInAppReceiptPayload(const unsigned char * payload, const size_t payloadLen, Isolate * isolate, Local<Object> receiptObject) {
        HandleScope handleScope(isolate);
        auto context = isolate->GetCurrentContext();
        const unsigned char * ptr = payload, * end = ptr + payloadLen;
        long len;
        int type, cls;
        
        ASN1_get_object(&ptr, &len, &type, &cls, end - ptr);
        if (type != V_ASN1_SET) throw Exception(ExceptionCodeFormat, __LINE__);
        
        while (ptr < end) {
            ASN1_get_object(&ptr, &len, &type, &cls, end - ptr);
            if (type != V_ASN1_SEQUENCE) throw Exception(ExceptionCodeFormat, __LINE__);
            
            const unsigned char * sequenceEnd = ptr + len, * nextPtr;
            
            std::unique_ptr<ASN1_INTEGER, ASN1IntDeleter> attrTypeVal(d2i_ASN1_INTEGER(nullptr, &ptr, sequenceEnd - ptr), ASN1IntDeleter());
            if (!attrTypeVal) throw Exception(ExceptionCodeFormat, __LINE__, "Attribute type");
            const auto attrType = ASN1_INTEGER_get(attrTypeVal.get());
            
            std::unique_ptr<ASN1_INTEGER, ASN1IntDeleter> attrVersionVal(d2i_ASN1_INTEGER(nullptr, &ptr, sequenceEnd - ptr), ASN1IntDeleter());
            if (!attrVersionVal) throw Exception(ExceptionCodeFormat, __LINE__, "Attribute version");
            if (ASN1_INTEGER_get(attrVersionVal.get()) != 1) throw Exception(ExceptionCodeFormat, __LINE__); // unsupported attribute version -> check docs -> update code
            
            ASN1_get_object(&ptr, &len, &type, &cls, sequenceEnd - ptr);
            if (type != V_ASN1_OCTET_STRING) throw Exception(ExceptionCodeFormat, __LINE__);
            
            nextPtr = ptr + len;
            
            switch (attrType) {
                case 1701: // Quantity, INTEGER, 'quantity'
                    if (_inAppReceiptFields & InAppReceiptFieldQuantity) {
                        std::unique_ptr<ASN1_INTEGER, ASN1IntDeleter> intVal(d2i_ASN1_INTEGER(nullptr, &ptr, sequenceEnd - ptr), ASN1IntDeleter());
                        if (!intVal) throw Exception(ExceptionCodeFormat, __LINE__, "Quantity");
                        VALIDATOR_CREATEDATAPROPERTY_NUM(isolate, context, receiptObject, "quantity", ASN1_INTEGER_get(intVal.get()))
                    }
                    break;
                    
                case 1711: // Web Order Line Item ID, INTEGER, 'web_order_line_item_id'
                    if (_inAppReceiptFields & InAppReceiptFieldWebOrderLineItemId) {
                        std::unique_ptr<ASN1_INTEGER, ASN1IntDeleter> intVal(d2i_ASN1_INTEGER(nullptr, &ptr, sequenceEnd - ptr), ASN1IntDeleter());
                        if (!intVal) throw Exception(ExceptionCodeFormat, __LINE__, "Web Order Line Item ID");
                        VALIDATOR_CREATEDATAPROPERTY_NUM(isolate, context, receiptObject, "web_order_line_item_id", ASN1_INTEGER_get(intVal.get()))
                    }
                    break;
                    
                case 1719: // Subscription Introductory Price Period, INTEGER, 'is_in_intro_offer_period'
                    if (_inAppReceiptFields & InAppReceiptFieldIsInIntroOfferPeriod) {
                        std::unique_ptr<ASN1_INTEGER, ASN1IntDeleter> intVal(d2i_ASN1_INTEGER(nullptr, &ptr, sequenceEnd - ptr), ASN1IntDeleter());
                        if (!intVal) throw Exception(ExceptionCodeFormat, __LINE__, "Subscription Introductory Price Period");
                        VALIDATOR_CREATEDATAPROPERTY_NUM(isolate, context, receiptObject, "is_in_intro_offer_period", ASN1_INTEGER_get(intVal.get()))
                    }
                    break;
                    
                case 1702: // Product Identifier, UTF8STRING, 'product_id'
                    if (_inAppReceiptFields & InAppReceiptFieldProductId) {
                        std::unique_ptr<ASN1_UTF8STRING, ASN1Utf8StringDeleter> utf8String(d2i_ASN1_UTF8STRING(nullptr, &ptr, sequenceEnd - ptr), ASN1Utf8StringDeleter());
                        if (!utf8String) throw Exception(ExceptionCodeFormat, __LINE__, "Product Identifier");
                        if (utf8String->length >= 0) {
                            VALIDATOR_CREATEDATAPROPERTY_STR_LEN(isolate, context, receiptObject, "product_id", reinterpret_cast<const char *>(utf8String->data), static_cast<int>(utf8String->length))
                        }
                    }
                    break;
                    
                case 1703: // Transaction Identifier, UTF8STRING, 'transaction_id'
                    if (_inAppReceiptFields & InAppReceiptFieldTransactionId) {
                        std::unique_ptr<ASN1_UTF8STRING, ASN1Utf8StringDeleter> utf8String(d2i_ASN1_UTF8STRING(nullptr, &ptr, sequenceEnd - ptr), ASN1Utf8StringDeleter());
                        if (!utf8String) throw Exception(ExceptionCodeFormat, __LINE__, "Transaction Identifier");
                        if (utf8String->length >= 0) {
                            VALIDATOR_CREATEDATAPROPERTY_STR_LEN(isolate, context, receiptObject, "transaction_id", reinterpret_cast<const char *>(utf8String->data), static_cast<int>(utf8String->length))
                        }
                    }
                    break;

                case 1705: // Original Transaction Identifier, UTF8STRING, 'original_transaction_id'
                    if (_inAppReceiptFields & InAppReceiptFieldOriginalTransactionId) {
                        std::unique_ptr<ASN1_UTF8STRING, ASN1Utf8StringDeleter> utf8String(d2i_ASN1_UTF8STRING(nullptr, &ptr, sequenceEnd - ptr), ASN1Utf8StringDeleter());
                        if (!utf8String) throw Exception(ExceptionCodeFormat, __LINE__, "Original Transaction Identifier");
                        if (utf8String->length >= 0) {
                            VALIDATOR_CREATEDATAPROPERTY_STR_LEN(isolate, context, receiptObject, "original_transaction_id", reinterpret_cast<const char *>(utf8String->data), static_cast<int>(utf8String->length))
                        }
                    }
                    break;

                case 1704: // Purchase Date, IA5STRING, interpreted as an RFC 3339 date, 'purchase_date'
                    if (_inAppReceiptFields & InAppReceiptFieldPurchaseDate) {
                        std::unique_ptr<ASN1_IA5STRING, ASN1Ia5StringDeleter> ia5String(d2i_ASN1_IA5STRING(nullptr, &ptr, sequenceEnd - ptr), ASN1Ia5StringDeleter());
                        if (!ia5String) throw Exception(ExceptionCodeFormat, __LINE__, "Purchase Date");
                        if (ia5String->length >= 0) {
                            VALIDATOR_CREATEDATAPROPERTY_STR_LEN(isolate, context, receiptObject, "purchase_date", reinterpret_cast<const char *>(ia5String->data), static_cast<int>(ia5String->length))
                            VALIDATOR_CREATEDATAPROPERTY_DATE_MS(isolate, context, receiptObject, "purchase_date_ms", millisecondsFromRFC3339DateString(reinterpret_cast<const char *>(ia5String->data)))
                        }
                    }
                    break;

                case 1706: // Original Purchase Date, IA5STRING, interpreted as an RFC 3339 date, 'original_purchase_date'
                    if (_inAppReceiptFields & InAppReceiptFieldOriginalPurchaseDate) {
                        std::unique_ptr<ASN1_IA5STRING, ASN1Ia5StringDeleter> ia5String(d2i_ASN1_IA5STRING(nullptr, &ptr, sequenceEnd - ptr), ASN1Ia5StringDeleter());
                        if (!ia5String) throw Exception(ExceptionCodeFormat, __LINE__, "Original Purchase Date");
                        if (ia5String->length >= 0) {
                            VALIDATOR_CREATEDATAPROPERTY_STR_LEN(isolate, context, receiptObject, "original_purchase_date", reinterpret_cast<const char *>(ia5String->data), static_cast<int>(ia5String->length))
                            VALIDATOR_CREATEDATAPROPERTY_DATE_MS(isolate, context, receiptObject, "original_purchase_date_ms", millisecondsFromRFC3339DateString(reinterpret_cast<const char *>(ia5String->data)))
                        }
                    }
                    break;

                case 1708: // Subscription Expiration Date, IA5STRING, interpreted as an RFC 3339 date, 'expires_date'
                    if (_inAppReceiptFields & InAppReceiptFieldExpiresDate) {
                        std::unique_ptr<ASN1_IA5STRING, ASN1Ia5StringDeleter> ia5String(d2i_ASN1_IA5STRING(nullptr, &ptr, sequenceEnd - ptr), ASN1Ia5StringDeleter());
                        if (!ia5String) throw Exception(ExceptionCodeFormat, __LINE__, "Subscription Expiration Date");
                        if (ia5String->length >= 0) {
                            VALIDATOR_CREATEDATAPROPERTY_STR_LEN(isolate, context, receiptObject, "expires_date", reinterpret_cast<const char *>(ia5String->data), static_cast<int>(ia5String->length))
                            VALIDATOR_CREATEDATAPROPERTY_DATE_MS(isolate, context, receiptObject, "expires_date_ms", millisecondsFromRFC3339DateString(reinterpret_cast<const char *>(ia5String->data)))
                        }
                    }
                    break;

                case 1712: // Cancellation Date, IA5STRING, interpreted as an RFC 3339 date, 'cancellation_date'
                    if (_inAppReceiptFields & InAppReceiptFieldCancellationDate) {
                        std::unique_ptr<ASN1_IA5STRING, ASN1Ia5StringDeleter> ia5String(d2i_ASN1_IA5STRING(nullptr, &ptr, sequenceEnd - ptr), ASN1Ia5StringDeleter());
                        if (!ia5String) throw Exception(ExceptionCodeFormat, __LINE__, "Cancellation Date");
                        if (ia5String->length >= 0) {
                            VALIDATOR_CREATEDATAPROPERTY_STR_LEN(isolate, context, receiptObject, "cancellation_date", reinterpret_cast<const char *>(ia5String->data), static_cast<int>(ia5String->length))
                            VALIDATOR_CREATEDATAPROPERTY_DATE_MS(isolate, context, receiptObject, "cancellation_date_ms", millisecondsFromRFC3339DateString(reinterpret_cast<const char *>(ia5String->data)))
                        }
                    }
                    break;
                    
                default:
                    break;
            }
            
            ptr = nextPtr;
        }
    }
    
    void Validator::validate(std::vector<uint8_t> && inReceipts, Isolate * isolate, Local<Object> receiptObject) {
        HandleScope handleScope(isolate);
        auto context = isolate->GetCurrentContext();
        const auto payloadBio = receiptPayload(std::move(inReceipts));
        unsigned char * payload = nullptr;
        const auto payloadLen = BIO_get_mem_data(payloadBio.get(), &payload);
        if (!payload || payloadLen == 0) throw Exception(ExceptionCodeInternal, __LINE__, "Receipt payload"); // update code
        
        const unsigned char * ptr = payload, * end = ptr + payloadLen;
        long len;
        int type, cls, guidFields = 0;
        
        ASN1_get_object(&ptr, &len, &type, &cls, end - ptr);
        if (type != V_ASN1_SET) throw Exception(ExceptionCodeFormat, __LINE__);
        
        auto receiptsArray = Array::New(isolate);
        uint32_t receiptsArrayIndex = 0;
        
        bool validateBundleIdentifier = _bundleIdentifier.length() > 0,
        validateVersion = _version.length() > 0,
        validateGUID = _GUID.size() > 0;
        
        ASN1ValidationReceiptFields receiptFields;
        
        while (ptr < end) {
            ASN1_get_object(&ptr, &len, &type, &cls, end - ptr);
            if (type != V_ASN1_SEQUENCE) throw Exception(ExceptionCodeFormat, __LINE__);
            
            const unsigned char * sequenceEnd = ptr + len;
            
            std::unique_ptr<ASN1_INTEGER, ASN1IntDeleter> attrTypeVal(d2i_ASN1_INTEGER(nullptr, &ptr, sequenceEnd - ptr), ASN1IntDeleter());
            if (!attrTypeVal) throw Exception(ExceptionCodeFormat, __LINE__, "Attribute type");
            const auto attrType = ASN1_INTEGER_get(attrTypeVal.get());
            
            std::unique_ptr<ASN1_INTEGER, ASN1IntDeleter> attrVersionVal(d2i_ASN1_INTEGER(nullptr, &ptr, sequenceEnd - ptr), ASN1IntDeleter());
            if (!attrVersionVal) throw Exception(ExceptionCodeFormat, __LINE__, "Attribute version");
            const auto attrVersion = ASN1_INTEGER_get(attrVersionVal.get());
            
            ASN1_get_object(&ptr, &len, &type, &cls, sequenceEnd - ptr);
            if (type != V_ASN1_OCTET_STRING) throw Exception(ExceptionCodeFormat, __LINE__);
            const unsigned char * octStr = ptr;
            const auto octStrLen = len;
            
            switch (attrType) {
                case 2: // Bundle Identifier, UTF8STRING, 'bundle_id'
                    if (attrVersion == 1) {
                        const unsigned char * tmpP = ptr;
                        std::unique_ptr<ASN1_UTF8STRING, ASN1Utf8StringDeleter> tmpUtf8(d2i_ASN1_UTF8STRING(nullptr, &tmpP, len), ASN1Utf8StringDeleter());
                        if (!tmpUtf8) throw Exception(ExceptionCodeFormat, __LINE__, "Bundle Identifier");
                        if (validateBundleIdentifier) {
                            validateBundleIdentifier = false;
                            std::string str; // Copy to std 'str'. See Case #1 at the end of file.
                            if (tmpUtf8->length > 0 && tmpUtf8->data) {
                                str = std::string(reinterpret_cast<const char *>(tmpUtf8->data), static_cast<size_t>(tmpUtf8->length));
                            }
                            if (str != _bundleIdentifier) throw Exception(ExceptionCodeValidation, __LINE__, "Bundle Identifier");
                        }
                        receiptFields.bundleIdentifier = ptr;
                        receiptFields.bundleIdentifierSize = len;
                        guidFields |= GUIDValidationFieldBundleId;
                        if (tmpUtf8->length >= 0) {
                            VALIDATOR_CREATEDATAPROPERTY_STR_LEN(isolate, context, receiptObject, "bundle_id", reinterpret_cast<const char *>(tmpUtf8->data), static_cast<int>(tmpUtf8->length))
                        }
                    } else {
                        throw Exception(ExceptionCodeFormat, __LINE__, "Bundle Identifier version"); // unsupported attribute version -> check docs -> update code
                    }
                    break;
                    
                case 4: // Opaque Value
                    if (attrVersion != 2) throw Exception(ExceptionCodeFormat, __LINE__, "Opaque Value version"); // unsupported attribute version -> check docs -> update code
                    receiptFields.opaqueValueV2 = ptr;
                    receiptFields.opaqueValueV2Size = len;
                    guidFields |= GUIDValidationFieldOpaqueValue;
                    break;
                    
                case 5: // SHA-1 Hash
                    if (attrVersion != 1) throw Exception(ExceptionCodeFormat, __LINE__, "SHA-1 Hash version"); // unsupported attribute version -> check docs -> update code
                    if (len != 20) throw Exception(ExceptionCodeFormat, __LINE__);
                    receiptFields.SHA1Hash = ptr;
                    receiptFields.SHA1HashSize = len;
                    guidFields |= GUIDValidationFieldSHA1;
                    break;
                    
                default:
                    break;
            }
            
            if (validateGUID && guidFields == GUIDValidationFieldAll) {
                validateGUID = false;
                if (!receiptFields.bundleIdentifier || !receiptFields.opaqueValueV2 || !receiptFields.SHA1Hash) throw Exception(ExceptionCodeValidation, __LINE__);
                EVP_MD_CTX * evp_ctx = EVP_MD_CTX_create();
                if (!evp_ctx) throw Exception(ExceptionCodeInternal, __LINE__);
                EVP_MD_CTX_init(evp_ctx);
                uint8_t digest[20] = { 0 };
                EVP_DigestInit_ex(evp_ctx, EVP_sha1(), nullptr);
                EVP_DigestUpdate(evp_ctx, _GUID.data(), _GUID.size()); // 1
                EVP_DigestUpdate(evp_ctx, receiptFields.opaqueValueV2, receiptFields.opaqueValueV2Size); // 2
                EVP_DigestUpdate(evp_ctx, receiptFields.bundleIdentifier, receiptFields.bundleIdentifierSize); // 3
                EVP_DigestFinal_ex(evp_ctx, digest, nullptr);
                EVP_MD_CTX_destroy(evp_ctx);
                if (memcmp(digest, receiptFields.SHA1Hash, 20) != 0) throw Exception(ExceptionCodeValidation, __LINE__, "SHA-1 Hash");
            }
            
            switch (attrType) {
                case 3: // App Version, UTF8STRING, 'application_version'
                    if (attrVersion == 1) {
                        const unsigned char * tmpP = ptr;
                        std::unique_ptr<ASN1_UTF8STRING, ASN1Utf8StringDeleter> tmpUtf8(d2i_ASN1_UTF8STRING(nullptr, &tmpP, len), ASN1Utf8StringDeleter());
                        if (!tmpUtf8) throw Exception(ExceptionCodeFormat, __LINE__, "App Version");
                        if (validateVersion) {
                            validateVersion = false;
                            std::string str; // Copy to std 'str'. See Case #1 at the end of file.
                            if (tmpUtf8->length > 0 && tmpUtf8->data) {
                                str = std::string(reinterpret_cast<const char *>(tmpUtf8->data), static_cast<size_t>(tmpUtf8->length));
                            }
                            if (str != _version) throw Exception(ExceptionCodeValidation, __LINE__, "App Version");
                        }
                        if (tmpUtf8->length >= 0) {
                            VALIDATOR_CREATEDATAPROPERTY_STR_LEN(isolate, context, receiptObject, "application_version", reinterpret_cast<const char *>(tmpUtf8->data), static_cast<int>(tmpUtf8->length))
                        }
                    } else {
                        throw Exception(ExceptionCodeFormat, __LINE__, "App Version version"); // unsupported attribute version -> check docs -> update code
                    }
                    break;
                    
                case 17: // In-App Purchase Receipt, 'in_app'
                    if (attrVersion == 1) {
                        auto inAppReceiptObject = Object::New(isolate);
                        parseInAppReceiptPayload(ptr, len, isolate, inAppReceiptObject);
#if (NODE_MAJOR_VERSION == 11 || NODE_MAJOR_VERSION == 10)
                        receiptsArray->Set(context, receiptsArrayIndex++, inAppReceiptObject).ToChecked();
#else
                        receiptsArray->Set(context, receiptsArrayIndex++, inAppReceiptObject).Check();
#endif
                    } else {
                        throw Exception(ExceptionCodeFormat, __LINE__, "In-App Purchase Receipt version"); // unsupported attribute version -> check docs -> update code
                    }
                    break;
                    
                default:
                    break;
            }
            
            ptr = octStr + octStrLen;
        }

        VALIDATOR_CREATEDATAPROPERTY_OBJ(isolate, context, receiptObject, "in_app", receiptsArray)
    }
    
    void Validator::New(const FunctionCallbackInfo<Value> & args) {
        Isolate * isolate = args.GetIsolate();
        HandleScope handleScope(isolate);
        auto context = isolate->GetCurrentContext();
        if (args.IsConstructCall()) {
            VALIDATOR_TRY
            Validator * validator = new Validator();
            validator->Wrap(args.This());
            VALIDATOR_CATCH_RET(isolate, context)
            args.GetReturnValue().Set(args.This());
        } else {
            auto constructor = args.Data().As<Object>()->GetInternalField(0).As<Function>();
            TryCatch trycatch(isolate);
            auto maybeResult = constructor->NewInstance(context, 0, nullptr);
            if (maybeResult.IsEmpty()) {
                if (trycatch.HasCaught()) {
                    trycatch.ReThrow();
                } else {
                    VALIDATOR_THROWEXCEPTION(isolate, "Can't instantiate Validator.")
                }
                return;
            }
            args.GetReturnValue().Set(maybeResult.ToLocalChecked());
        }
    }
    
    void Validator::Version(Local<String> property, const PropertyCallbackInfo<Value> & info) {
        Isolate * isolate = info.GetIsolate();
        HandleScope handleScope(isolate);
        auto context = isolate->GetCurrentContext();
        VALIDATOR_TRY
        Validator * validator = ObjectWrap::Unwrap<Validator>(info.Holder());
        if (validator->_version.length() > 0) {
            info.GetReturnValue().Set(VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, validator->_version.c_str()));
        } else {
            info.GetReturnValue().SetUndefined();
        }
        VALIDATOR_CATCH_RET(isolate, context)
    }

    void Validator::SetVersion(Local<String> property, Local<Value> value, const PropertyCallbackInfo<void> & info) {
        Isolate * isolate = info.GetIsolate();
        HandleScope handleScope(isolate);
        auto context = isolate->GetCurrentContext();
        VALIDATOR_TRY
        Validator * validator = ObjectWrap::Unwrap<Validator>(info.Holder());
        validator->_version.clear();
        if (value->IsString()) {
            String::Utf8Value str(isolate, value);
            if (str.length() > 0) {
                validator->_version = *str;
            }
        }
        VALIDATOR_CATCH_RET(isolate, context)
    }

    void Validator::BundleIdentifier(Local<String> property, const PropertyCallbackInfo<Value> & info) {
        Isolate * isolate = info.GetIsolate();
        HandleScope handleScope(isolate);
        auto context = isolate->GetCurrentContext();
        VALIDATOR_TRY
        Validator * validator = ObjectWrap::Unwrap<Validator>(info.Holder());
        if (validator->_bundleIdentifier.length() > 0) {
            info.GetReturnValue().Set(VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, validator->_bundleIdentifier.c_str()));
        } else {
            info.GetReturnValue().SetUndefined();
        }
        VALIDATOR_CATCH_RET(isolate, context)
    }

    void Validator::SetBundleIdentifier(Local<String> property, Local<Value> value, const PropertyCallbackInfo<void> & info) {
        Isolate * isolate = info.GetIsolate();
        HandleScope handleScope(isolate);
        auto context = isolate->GetCurrentContext();
        VALIDATOR_TRY
        Validator * validator = ObjectWrap::Unwrap<Validator>(info.Holder());
        validator->_bundleIdentifier.clear();
        if (value->IsString()) {
            String::Utf8Value str(isolate, value);
            if (str.length() > 0) {
                validator->_bundleIdentifier = *str;
            }
        }
        VALIDATOR_CATCH_RET(isolate, context)
    }

    void Validator::GUID(Local<String> property, const PropertyCallbackInfo<Value> & info) {
        Isolate * isolate = info.GetIsolate();
        HandleScope handleScope(isolate);
        auto context = isolate->GetCurrentContext();
        Validator * validator = ObjectWrap::Unwrap<Validator>(info.Holder());
        VALIDATOR_TRY
        const auto GUIDSize = validator->_GUID.size();
        if (GUIDSize > 0) {
#if (NODE_MAJOR_VERSION == 12 || NODE_MAJOR_VERSION == 11 || NODE_MAJOR_VERSION == 10)
            info.GetReturnValue().Set(ArrayBuffer::New(isolate, validator->_GUID.data(), GUIDSize));
#else
            auto backingStore = ArrayBuffer::NewBackingStore(isolate, GUIDSize);
            if (!backingStore) throw Exception(ExceptionCodeInternal, __LINE__, "NewBackingStore");
            memcpy(backingStore->Data(), validator->_GUID.data(), GUIDSize);
            info.GetReturnValue().Set(ArrayBuffer::New(isolate, std::move(backingStore)));
#endif
        } else {
            info.GetReturnValue().SetUndefined();
        }
        VALIDATOR_CATCH_RET(isolate, context)
    }

    void Validator::SetGUID(Local<String> property, Local<Value> value, const PropertyCallbackInfo<void> & info) {
        Isolate * isolate = info.GetIsolate();
        HandleScope handleScope(isolate);
        auto context = isolate->GetCurrentContext();
        VALIDATOR_TRY
        Validator * validator = ObjectWrap::Unwrap<Validator>(info.Holder());
        validator->_GUID.clear();
        if (value->IsString()) {
            String::Utf8Value str(isolate, value);
            if (str.length() > 0) {
                validator->_GUID = decodeBase64String(*str);
            }
        } else if (value->IsArrayBuffer()) {
            const auto arrayBuffer = Local<ArrayBuffer>::Cast(value);
#if (NODE_MAJOR_VERSION == 12 || NODE_MAJOR_VERSION == 11 || NODE_MAJOR_VERSION == 10)
            const auto contents = arrayBuffer->GetContents();
            const size_t byteLength = contents.ByteLength();
            if (byteLength > 0) {
                std::vector<uint8_t> v;
                v.resize(byteLength);
                memcpy(v.data(), contents.Data(), byteLength);
                validator->_GUID = std::move(v);
            }
#else
            const auto backingStore = arrayBuffer->GetBackingStore();
            const size_t byteLength = backingStore ? backingStore->ByteLength() : 0;
            if (byteLength > 0) {
                std::vector<uint8_t> v;
                v.resize(byteLength);
                memcpy(v.data(), backingStore->Data(), byteLength);
                validator->_GUID = std::move(v);
            }
#endif
        }
        VALIDATOR_CATCH_RET(isolate, context)
    }

    void Validator::RootCertificate(Local<String> property, const PropertyCallbackInfo<Value> & info) {
        Isolate * isolate = info.GetIsolate();
        HandleScope handleScope(isolate);
        auto context = isolate->GetCurrentContext();
        VALIDATOR_TRY
        Validator * validator = ObjectWrap::Unwrap<Validator>(info.Holder());
        const auto certSize = validator->_rootCertificate.size();
        if (certSize > 0) {
#if (NODE_MAJOR_VERSION == 12 || NODE_MAJOR_VERSION == 11 || NODE_MAJOR_VERSION == 10)
            info.GetReturnValue().Set(ArrayBuffer::New(isolate, validator->_rootCertificate.data(), certSize));
#else
            auto backingStore = ArrayBuffer::NewBackingStore(isolate, certSize);
            if (!backingStore) throw Exception(ExceptionCodeInternal, __LINE__, "NewBackingStore");
            memcpy(backingStore->Data(), validator->_rootCertificate.data(), certSize);
            info.GetReturnValue().Set(ArrayBuffer::New(isolate, std::move(backingStore)));
#endif
        } else {
            const auto certificate = AppleIncRootCertificateFile();
#if (NODE_MAJOR_VERSION == 12 || NODE_MAJOR_VERSION == 11 || NODE_MAJOR_VERSION == 10)
            info.GetReturnValue().Set(ArrayBuffer::New(isolate, certificate.first, certificate.second));
#else
            auto backingStore = ArrayBuffer::NewBackingStore(isolate, certificate.second);
            if (!backingStore) throw Exception(ExceptionCodeInternal, __LINE__, "NewBackingStore");
            memcpy(backingStore->Data(), certificate.first, certificate.second);
            info.GetReturnValue().Set(ArrayBuffer::New(isolate, std::move(backingStore)));
#endif
        }
        VALIDATOR_CATCH_RET(isolate, context)
    }

    void Validator::SetRootCertificate(Local<String> property, Local<Value> value, const PropertyCallbackInfo<void> & info) {
        Isolate * isolate = info.GetIsolate();
        HandleScope handleScope(isolate);
        auto context = isolate->GetCurrentContext();
        VALIDATOR_TRY
        Validator * validator = ObjectWrap::Unwrap<Validator>(info.Holder());
        validator->_rootCertificate.clear();
        if (value->IsArrayBuffer()) {
            const auto arrayBuffer = Local<ArrayBuffer>::Cast(value);
#if (NODE_MAJOR_VERSION == 12 || NODE_MAJOR_VERSION == 11 || NODE_MAJOR_VERSION == 10)
            const auto contents = arrayBuffer->GetContents();
            const size_t byteLength = contents.ByteLength();
            if (byteLength > 0) {
                std::vector<uint8_t> v;
                v.resize(byteLength);
                memcpy(v.data(), contents.Data(), byteLength);
                validator->_rootCertificate = std::move(v);
            }
#else
            const auto backingStore = arrayBuffer->GetBackingStore();
            const size_t byteLength = backingStore ? backingStore->ByteLength() : 0;
            if (byteLength > 0) {
                std::vector<uint8_t> v;
                v.resize(byteLength);
                memcpy(v.data(), backingStore->Data(), byteLength);
                validator->_rootCertificate = std::move(v);
            }
#endif
        }
        VALIDATOR_CATCH_RET(isolate, context)
    }

    void Validator::InAppReceiptFields(Local<String> property, const PropertyCallbackInfo<Value> & info) {
        Isolate * isolate = info.GetIsolate();
        HandleScope handleScope(isolate);
        auto context = isolate->GetCurrentContext();
        VALIDATOR_TRY
        Validator * validator = ObjectWrap::Unwrap<Validator>(info.Holder());
        info.GetReturnValue().Set(Int32::New(isolate, validator->_inAppReceiptFields));
        VALIDATOR_CATCH_RET(isolate, context)
    }

    void Validator::SetInAppReceiptFields(Local<String> property, Local<Value> value, const PropertyCallbackInfo<void> & info) {
        Isolate * isolate = info.GetIsolate();
        HandleScope handleScope(isolate);
        auto context = isolate->GetCurrentContext();
        VALIDATOR_TRY
        Validator * validator = ObjectWrap::Unwrap<Validator>(info.Holder());
        uint32_t fields = InAppReceiptFieldAll;
        if (value->IsNumber()) {
            const auto bitMaskValue = value->ToNumber(context).ToLocalChecked()->Value();
            if (bitMaskValue >= 0 && bitMaskValue <= InAppReceiptFieldAll) {
                fields = static_cast<uint32_t>(bitMaskValue);
            }
        }
        validator->_inAppReceiptFields = fields;
        VALIDATOR_CATCH_RET(isolate, context)
    }

    void Validator::Validate(const FunctionCallbackInfo<Value> & args) {
        Isolate * isolate = args.GetIsolate();
        HandleScope handleScope(isolate);
        auto context = isolate->GetCurrentContext();
        auto receiptObject = Object::New(isolate);
        VALIDATOR_TRY
        Validator * validator = ObjectWrap::Unwrap<Validator>(args.Holder());
        std::vector<uint8_t> inReceipt;
        if (args.Length() > 0) {
            if (args[0]->IsString()) {
                String::Utf8Value str(isolate, args[0]);
                if (str.length() > 0) {
                    inReceipt = decodeBase64String(*str);
                } else {
                    throw Exception(ExceptionCodeInput, __LINE__, "Receipt is empty");
                }
            } else if (args[0]->IsArrayBuffer()) {
                const auto arrayBuffer = Local<ArrayBuffer>::Cast(args[0]);
#if (NODE_MAJOR_VERSION == 12 || NODE_MAJOR_VERSION == 11 || NODE_MAJOR_VERSION == 10)
                const auto contents = arrayBuffer->GetContents();
                const size_t byteLength = contents.ByteLength();
                if (byteLength > 0) {
                    inReceipt.resize(byteLength);
                    memcpy(inReceipt.data(), contents.Data(), byteLength);
                }
#else
                const auto backingStore = arrayBuffer->GetBackingStore();
                const size_t byteLength = backingStore ? backingStore->ByteLength() : 0;
                if (byteLength > 0) {
                    inReceipt.resize(byteLength);
                    memcpy(inReceipt.data(), backingStore->Data(), byteLength);
                }
#endif
                else {
                    throw Exception(ExceptionCodeInput, __LINE__, "Receipt is empty");
                }
            }
        }
        if (inReceipt.size() > 0) {
            validator->validate(std::move(inReceipt), isolate, receiptObject);
        } else {
            throw Exception(ExceptionCodeInput, __LINE__, "Receipt is empty");
        }
        VALIDATOR_CATCH_RET(isolate, context)
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
        ctorTpl->SetClassName(VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "Validator"));
        
        auto ctorInstTpl = ctorTpl->InstanceTemplate();
        ctorInstTpl->SetInternalFieldCount(1);
        
        // (new Validator(...)).<func>(...)
        auto ctorProtoTpl = ctorTpl->PrototypeTemplate();
        ctorProtoTpl->Set(VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "validate"), FunctionTemplate::New(isolate, Validator::Validate), static_cast<PropertyAttribute>(ReadOnly | DontDelete));
        
        // (new Validator(...)).<prop>
        ctorInstTpl->SetAccessor(VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "version"), Validator::Version, Validator::SetVersion, Local<Value>(), DEFAULT, DontDelete);
        ctorInstTpl->SetAccessor(VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "bundleIdentifier"), Validator::BundleIdentifier, Validator::SetBundleIdentifier, Local<Value>(), DEFAULT, DontDelete);
        ctorInstTpl->SetAccessor(VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "GUID"), Validator::GUID, Validator::SetGUID, Local<Value>(), DEFAULT, DontDelete);
        ctorInstTpl->SetAccessor(VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "rootCertificate"), Validator::RootCertificate, Validator::SetRootCertificate, Local<Value>(), DEFAULT, DontDelete);
        ctorInstTpl->SetAccessor(VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "inAppReceiptFields"), Validator::InAppReceiptFields, Validator::SetInAppReceiptFields, Local<Value>(), DEFAULT, DontDelete);
        
        auto constructor = ctorTpl->GetFunction(context).ToLocalChecked();
        dataObject->SetInternalField(0, constructor);
        exports->Set(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "Validator"), constructor).FromJust();
    }
    
} // validator

static void ValidatorModuleInit(Local<Object> exports) {
    Isolate * isolate = exports->GetIsolate();
    HandleScope handleScope(isolate);
    auto context = isolate->GetCurrentContext();
    
    auto errorCodeObject = Object::New(isolate);
#if (NODE_MAJOR_VERSION == 12 || NODE_MAJOR_VERSION == 11 || NODE_MAJOR_VERSION == 10)
    errorCodeObject->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "internal"), Uint32::NewFromUnsigned(isolate, validator::ExceptionCodeInternal), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).ToChecked();
    errorCodeObject->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "input"), Uint32::NewFromUnsigned(isolate, validator::ExceptionCodeInput), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).ToChecked();
    errorCodeObject->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "format"), Uint32::NewFromUnsigned(isolate, validator::ExceptionCodeFormat), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).ToChecked();
    errorCodeObject->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "validation"), Uint32::NewFromUnsigned(isolate, validator::ExceptionCodeValidation), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).ToChecked();
#else
    errorCodeObject->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "internal"), Uint32::NewFromUnsigned(isolate, validator::ExceptionCodeInternal), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).Check();
    errorCodeObject->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "input"), Uint32::NewFromUnsigned(isolate, validator::ExceptionCodeInput), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).Check();
    errorCodeObject->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "format"), Uint32::NewFromUnsigned(isolate, validator::ExceptionCodeFormat), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).Check();
    errorCodeObject->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "validation"), Uint32::NewFromUnsigned(isolate, validator::ExceptionCodeValidation), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).Check();
#endif
    exports->Set(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "ErrorCode"), errorCodeObject).FromJust();
    
    auto inAppReceiptField = Object::New(isolate);
#if (NODE_MAJOR_VERSION == 12 || NODE_MAJOR_VERSION == 11 || NODE_MAJOR_VERSION == 10)
    inAppReceiptField->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "quantity"), Uint32::NewFromUnsigned(isolate, validator::InAppReceiptFieldQuantity), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).ToChecked();
    inAppReceiptField->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "web_order_line_item_id"), Uint32::NewFromUnsigned(isolate, validator::InAppReceiptFieldWebOrderLineItemId), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).ToChecked();
    inAppReceiptField->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "is_in_intro_offer_period"), Uint32::NewFromUnsigned(isolate, validator::InAppReceiptFieldIsInIntroOfferPeriod), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).ToChecked();
    inAppReceiptField->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "product_id"), Uint32::NewFromUnsigned(isolate, validator::InAppReceiptFieldProductId), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).ToChecked();
    inAppReceiptField->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "transaction_id"), Uint32::NewFromUnsigned(isolate, validator::InAppReceiptFieldTransactionId), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).ToChecked();
    inAppReceiptField->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "original_transaction_id"), Uint32::NewFromUnsigned(isolate, validator::InAppReceiptFieldOriginalTransactionId), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).ToChecked();
    inAppReceiptField->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "purchase_date"), Uint32::NewFromUnsigned(isolate, validator::InAppReceiptFieldPurchaseDate), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).ToChecked();
    inAppReceiptField->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "original_purchase_date"), Uint32::NewFromUnsigned(isolate, validator::InAppReceiptFieldOriginalPurchaseDate), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).ToChecked();
    inAppReceiptField->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "expires_date"), Uint32::NewFromUnsigned(isolate, validator::InAppReceiptFieldExpiresDate), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).ToChecked();
    inAppReceiptField->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "cancellation_date"), Uint32::NewFromUnsigned(isolate, validator::InAppReceiptFieldCancellationDate), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).ToChecked();
    inAppReceiptField->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "all"), Uint32::NewFromUnsigned(isolate, validator::InAppReceiptFieldAll), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).ToChecked();
#else
    inAppReceiptField->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "quantity"), Uint32::NewFromUnsigned(isolate, validator::InAppReceiptFieldQuantity), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).Check();
    inAppReceiptField->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "web_order_line_item_id"), Uint32::NewFromUnsigned(isolate, validator::InAppReceiptFieldWebOrderLineItemId), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).Check();
    inAppReceiptField->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "is_in_intro_offer_period"), Uint32::NewFromUnsigned(isolate, validator::InAppReceiptFieldIsInIntroOfferPeriod), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).Check();
    inAppReceiptField->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "product_id"), Uint32::NewFromUnsigned(isolate, validator::InAppReceiptFieldProductId), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).Check();
    inAppReceiptField->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "transaction_id"), Uint32::NewFromUnsigned(isolate, validator::InAppReceiptFieldTransactionId), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).Check();
    inAppReceiptField->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "original_transaction_id"), Uint32::NewFromUnsigned(isolate, validator::InAppReceiptFieldOriginalTransactionId), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).Check();
    inAppReceiptField->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "purchase_date"), Uint32::NewFromUnsigned(isolate, validator::InAppReceiptFieldPurchaseDate), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).Check();
    inAppReceiptField->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "original_purchase_date"), Uint32::NewFromUnsigned(isolate, validator::InAppReceiptFieldOriginalPurchaseDate), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).Check();
    inAppReceiptField->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "expires_date"), Uint32::NewFromUnsigned(isolate, validator::InAppReceiptFieldExpiresDate), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).Check();
    inAppReceiptField->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "cancellation_date"), Uint32::NewFromUnsigned(isolate, validator::InAppReceiptFieldCancellationDate), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).Check();
    inAppReceiptField->DefineOwnProperty(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "all"), Uint32::NewFromUnsigned(isolate, validator::InAppReceiptFieldAll), static_cast<PropertyAttribute>(ReadOnly | DontDelete)).Check();
#endif
    exports->Set(context, VALIDATOR_NEW_LOCAL_STRING_FROMUTF8(isolate, "InAppReceiptField"), inAppReceiptField).FromJust();
    
    validator::Validator::Init(exports);
}

NODE_MODULE(aiap_local_validator, ValidatorModuleInit)

/// Case #1
// std::string s1{"abcd"};
// std::string s2{"ab\0cd", 5};
// std::cout << s1 << " len:" << s1.length() << '\n';      // abcd len:4
// std::cout << s2 << " len:" << s2.length() << '\n';      // abcd len:5
// std::cout << ((s1 == s2) ? "true" : "false") << '\n';   // false
