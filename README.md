## Apple's in-app purchases local, on-device, receipt validator


### Node.js native module API reference.
-----------

* module  
  * [ErrorCode](#enum_errorcode)
    * [.internal](#enum_errorcode_internal) ⇒ ```Number```
    * [.input](#enum_errorcode_input) ⇒ ```Number```
    * [.format](#enum_errorcode_format) ⇒ ```Number```
    * [.validation](#enum_errorcode_validation) ⇒ ```Number```
  * [Validator](#class_validator)
    * [new Validator()](#class_validator_new)
    * [Validator()](#class_validator_new) ⇒ <code>[new Validator()](#class_validator_new)</code>
    * [.version](#class_validator_version) ⇔ ```String```|```Undefined```
    * [.bundleIdentifier](#class_validator_bundle_identifier) ⇔ ```String```|```Undefined```
    * [.GUID](#class_validator_guid) ⇒ ```ArrayBuffer```, ⇐ ```ArrayBuffer```|```String```
    * [.rootCertificate](#class_validator_root_certificate) ⇔ ```ArrayBuffer```
    * [.validate(receipt)](#class_validator_validate) ⇒ ```Object```
    
    
### <a name="enum_errorcode"></a>ErrorCode
Exported object with exception error codes. Use the 'code' property of the Error object.

#### <a name="enum_errorcode_internal"></a>ErrorCode.internal ⇒ Number
The required amount of memory can't be alocated or can't instantiate some object.

#### <a name="enum_errorcode_input"></a>ErrorCode.input ⇒ Number
The provided argument has unsupported type or incorrect value.

#### <a name="enum_errorcode_format"></a>ErrorCode.format ⇒ Number
The receipt has unsupported type of the data or property version. Need update the code and use latest version.

#### <a name="enum_errorcode_validation"></a>ErrorCode.validation ⇒ Number
The provided input arguments and the receipt can't be evaluated. 

### <a name="class_validator"></a>Validator
Exported validator.

#### <a name="class_validator_new"></a>new Validator()
Constructs new validator.

### <a name="class_validator_version"></a>Validator.version  ⇔ String|Undefined
Provide the application's version to check with the provided receipt.
If this value exists and the receipt contains different version ⇒ Exception(ErrorCode.validation).

### <a name="class_validator_bundle_identifier"></a>Validator.bundleIdentifier  ⇔ String|Undefined
Provide the application's bundle identifier to check with the provided receipt.
If this value exists and the receipt contains different bundle identifier ⇒ Exception(ErrorCode.validation).

### <a name="class_validator_bundle_identifier"></a>Validator.GUID ⇒ ArrayBuffer, ⇐ ArrayBuffer|String
Provide the application's GUID to check with the provided receipt.
If this value exists and the receipt contains different GUID ⇒ Exception(ErrorCode.validation).

### <a name="class_validator_bundle_identifier"></a>Validator.rootCertificate ⇔ ArrayBuffer
Instead of bundled 'Apple Inc Root Certificate' provide and use your own.

### <a name="class_validator_validate"></a>Validator.validate(receipt) ⇔ Object 
Validates the provided receipt as a Base64 String or as ArrayBuffer and returns the decrypted App Receipt and array of In-App Purchase Receipt's 
If the 'version' and/or 'bundleIdentifier' and/or 'GUID' was provided and the decrypted receipt contains different values ⇒ Exception(ErrorCode.validation). 

https://developer.apple.com/library/archive/releasenotes/General/ValidateAppStoreReceipt/Chapters/ReceiptFields.html#//apple_ref/doc/uid/TP40010573-CH106-SW1


### Installation via npm package.json
-----------

```json
{
  "engines": {
    "node": ">=13.0.0",
    "npm": ">=6.0.0"
  },
  "dependencies": {
    "aiap-local-validator": "0.0.1"
  }
}
```


### Example
-----------

```javascript
const { Validator, ErrorCode } = require('aiap-local-validator');

try {
    const validator = new Validator();
    validator.bundleIdentifier = 'my.com';
    validator.version = '123';
    validator.GUID = 'Base64 GUID' | ArrayBuffer;
    
    const receipt = validator.validate('Base64 receipt' | ArrayBuffer);
    // User 'receipt'. For more info, see 'Supported fields' section. 
} catch (error) {
    switch (error.code) {
        case ErrorCode.input:
            break;
    }
}
```


### Supported fields
All 'App Receipt' and 'In-App Purchase Receipt' fields which are described and have a valid 'ASN.1 Field Type' are present.

https://developer.apple.com/library/archive/releasenotes/General/ValidateAppStoreReceipt/Chapters/ReceiptFields.html#//apple_ref/doc/uid/TP40010573-CH106-SW1


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
