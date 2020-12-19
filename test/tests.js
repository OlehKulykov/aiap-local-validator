'use strict';

const { Validator, ErrorCode } = require('./../');

const validator = new Validator();
    
if (typeof validator.bundleIdentifier !== 'undefined') throw '';
validator.bundleIdentifier = 'my.com';
if (typeof validator.bundleIdentifier !== 'string') throw '';
if (validator.bundleIdentifier !== 'my.com') throw '';
validator.bundleIdentifier = undefined;
if (typeof validator.bundleIdentifier !== 'undefined') throw '';

if (typeof validator.version !== 'undefined') throw '';
validator.version = '123';
if (typeof validator.version !== 'string') throw '';
if (validator.version !== '123') throw '';
validator.version = undefined;
if (typeof validator.version !== 'undefined') throw '';
    
if (typeof validator.GUID !== 'undefined') throw '';
validator.GUID = '0DlJQYXPRZuCYxbBYR6fXA==';
if (typeof validator.GUID !== 'object') throw '';
if (validator.GUID.byteLength !== 16) throw '';
validator.GUID = undefined;
if (typeof validator.GUID !== 'undefined') throw '';

if (typeof validator.rootCertificate !== 'object') throw '';
validator.rootCertificate = undefined;
if (typeof validator.rootCertificate !== 'object') throw '';
if (validator.rootCertificate.byteLength <= 0) throw '';

let passed = false;
try {
    const receipt = validator.validate(undefined);
} catch (error) {
    switch (error.code) {
        case ErrorCode.input:
            passed = true;
            break;
    }
}
if (!passed) throw '';
