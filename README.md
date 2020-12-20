## Apple's in-app purchases local, on-device, receipt validator module for node.js.
[![Build Status](https://travis-ci.org/OlehKulykov/aiap-local-validator.svg?branch=master)](https://travis-ci.org/OlehKulykov/aiap-local-validator)
-----------

This module implements in-app purchases local receipt validation.
The module has no external dependencies and implemented as a native module. 
For more info check: https://developer.apple.com/library/archive/releasenotes/General/ValidateAppStoreReceipt/Chapters/ValidateLocally.html

### Node.js native module API reference.
-----------

* module  
  * [ErrorCode](#enum_errorcode)
    * [.internal](#enum_errorcode_internal) ⇒ ```Number```
    * [.input](#enum_errorcode_input) ⇒ ```Number```
    * [.format](#enum_errorcode_format) ⇒ ```Number```
    * [.validation](#enum_errorcode_validation) ⇒ ```Number```
  * [InAppReceiptField](#enum_inappreceiptfield)
    * [.quantity](#enum_inappreceiptfield_quantity) ⇒ ```Number```
    * [.web_order_line_item_id](#enum_inappreceiptfield_web_order_line_item_id) ⇒ ```Number```
    * [.is_in_intro_offer_period](#enum_inappreceiptfield_is_in_intro_offer_period) ⇒ ```Number```
    * [.product_id](#enum_inappreceiptfield_product_id) ⇒ ```Number```
    * [.transaction_id](#enum_inappreceiptfield_transaction_id) ⇒ ```Number```
    * [.original_transaction_id](#enum_inappreceiptfield_original_transaction_id) ⇒ ```Number```
    * [.purchase_date](#enum_inappreceiptfield_purchase_date) ⇒ ```Number```
    * [.original_purchase_date](#enum_inappreceiptfield_original_purchase_date) ⇒ ```Number```
    * [.expires_date](#enum_inappreceiptfield_expires_date) ⇒ ```Number```
    * [.cancellation_date](#enum_inappreceiptfield_cancellation_date) ⇒ ```Number```
    * [.all](#enum_inappreceiptfield_all) ⇒ ```Number```
  * [Validator](#class_validator)
    * [new Validator()](#class_validator_new)
    * [Validator()](#class_validator_new) ⇒ <code>[new Validator()](#class_validator_new)</code>
    * [.version](#class_validator_version) ⇔ ```String```|```Undefined```
    * [.bundleIdentifier](#class_validator_bundle_identifier) ⇔ ```String```|```Undefined```
    * [.GUID](#class_validator_guid) ⇒ ```ArrayBuffer```, ⇐ ```ArrayBuffer```|```String```
    * [.inAppReceiptFields](#class_validator_inappreceiptfields)  ⇔ ```Number```
    * [.rootCertificate](#class_validator_root_certificate) ⇔ ```ArrayBuffer```
    * [.validate(receipt)](#class_validator_validate) ⇒ ```Object```
    
    
### <a name="enum_errorcode"></a>ErrorCode
Exported object with exception error codes. Use the 'code' property of the Error object.

#### <a name="enum_errorcode_internal"></a>ErrorCode.internal ⇒ Number
The required amount of memory can't be alocated or can't instantiate some object.

#### <a name="enum_errorcode_input"></a>ErrorCode.input ⇒ Number
The provided argument has unsupported type or incorrect value.

#### <a name="enum_errorcode_format"></a>ErrorCode.format ⇒ Number
The receipt has unsupported type of the data or property version. Need update the code, report npm module and update project to use the latest version.

#### <a name="enum_errorcode_validation"></a>ErrorCode.validation ⇒ Number
Any validation error. 

### <a name="enum_inappreceiptfield"></a>InAppReceiptField
Represents bit-mask values of the 'InAppReceiptField' fields. The name of the emum values are same as in ouput.

### <a name="class_validator"></a>Validator
Exported validator.

#### <a name="class_validator_new"></a>new Validator()
Constructs new validator.

### <a name="class_validator_version"></a>Validator.version ⇔ String|Undefined
Default: ```undefined```.
Provide the application's version to check with the receipt.
If this value exists and the receipt contains different version ⇒ Exception(ErrorCode.validation).

### <a name="class_validator_bundle_identifier"></a>Validator.bundleIdentifier ⇔ String|Undefined
Default: ```undefined```.
Provide the application's bundle identifier to check with the receipt.
If this value exists and the receipt contains different bundle identifier ⇒ Exception(ErrorCode.validation).

### <a name="class_validator_guid"></a>Validator.GUID ⇒ ArrayBuffer, ⇐ ArrayBuffer|String
Default: ```undefined```.
Provide the application's GUID as a Base64 string or as ArrayBuffer of raw GUID data to check with the receipt.
If this value exists and the receipt contains different GUID ⇒ Exception(ErrorCode.validation).
```swift
var deviceIdentifier = UIDevice.current.identifierForVendor?.uuid
let rawDeviceIdentifierPointer = withUnsafePointer(to: &deviceIdentifier) {
    return UnsafeRawPointer($0)
}
let GUID = NSData(bytes: rawDeviceIdentifierPointer, length: 16)
```

### <a name="class_validator_inappreceiptfields"></a>Validator.inAppReceiptFields ⇔ Number
Default: ```InAppReceiptField.all```.
Bit-mask value of the 'In App Receipt' fields.

### <a name="class_validator_root_certificate"></a>Validator.rootCertificate ⇔ ArrayBuffer
Default: bundled raw data of the 'Apple Inc Root Certificate' as ```ArrayBuffer```.
Instead of bundled 'Apple Inc Root Certificate' provide and use your own.
To reset to a default bundled certificate, provide undefined value.

### <a name="class_validator_validate"></a>Validator.validate(receipt) ⇔ Object 
Validates the provided receipt as a Base64 String or as ArrayBuffer of raw data and returns the decrypted App Receipt and array of In-App Purchase Receipt's. 
If the 'version' and/or 'bundleIdentifier' and/or 'GUID' was provided and the decrypted receipt contains different values ⇒ Exception(ErrorCode.validation). 

https://developer.apple.com/library/archive/releasenotes/General/ValidateAppStoreReceipt/Chapters/ReceiptFields.html


### Installation via npm package.json
-----------

```json
{
  "engines": {
    "node": ">=13.0.0",
    "npm": ">=6.0.0"
  },
  "dependencies": {
    "aiap-local-validator": "^0.0.7"
  }
}
```


### Example
-----------

```javascript
const { Validator, ErrorCode, InAppReceiptField } = require('aiap-local-validator');

try {
    const validator = new Validator();
    
    // Optinaly select fields of the 'In App Receipt'.
    validator.inAppReceiptFields = InAppReceiptField.expires_date | InAppReceiptField.product_id;
    
    // Optionaly, but recommended, validate the receipt with 'bundleIdentifier', 'version' and 'GUID'.
    validator.bundleIdentifier = 'my.cool.app'; // If validation was failed, the receipt was created by another app -> invalid.
    validator.version = '123'; // If validation was failed, the receipt was created by another version of the app -> invalid.
    validator.GUID = '<Base64 GUID>' | ArrayBuffer; // If validation was failed, the receipt was created on another device -> invalid.
    
    const receipt = validator.validate('<Base64 receipt>' | ArrayBuffer); 
} catch (error) {
    switch (error.code) {
        case ErrorCode.input: break;
        case ErrorCode.validation: break;
        ...
    }
}
```


### Supported fields
All 'App Receipt' and 'In-App Purchase Receipt' fields which are described and have a valid 'ASN.1 Field Type' are supported.

https://developer.apple.com/library/archive/releasenotes/General/ValidateAppStoreReceipt/Chapters/ReceiptFields.html


### License
-----------
MIT License

Copyright (c) 2020 OlehKulykov <olehkulykov@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
