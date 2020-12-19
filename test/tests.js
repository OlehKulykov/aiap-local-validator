'use strict';

const https = require('https');
const { Validator, ErrorCode, InAppReceiptField } = require('./../');

function appendBuffer(buffer1, buffer2) {
    let tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
    tmp.set(new Uint8Array(buffer1), 0);
    tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
    return tmp.buffer;
};

const options = new URL('https://www.apple.com/appleca/AppleIncRootCertificate.cer');
const request = https.request(options, resp => {
    let data = undefined;
    resp.on('data', chunk => {
        data = data ? appendBuffer(data, chunk) : chunk;
    });
    resp.on('end', () => {
        if (!data) throw '';
        const validator = new Validator();
        const cert = new Uint8Array(validator.rootCertificate);
        if (data.byteLength !== cert.byteLength) throw '';
        for (let i = 0, n = data.byteLength; i < n; i++) {
            if (data[i] !== cert[i]) throw '';
        }
        console.log('Root certificate: ok');
    });
});
request.on('error', error => {
    throw error;
});
request.end();

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

if (typeof validator.inAppReceiptFields !== 'number') throw '';
let fields = InAppReceiptField.quantity | InAppReceiptField.expires_date | InAppReceiptField.product_id;
validator.inAppReceiptFields = fields;
if (validator.inAppReceiptFields !== fields) throw '';

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
