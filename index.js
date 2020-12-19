'use strict';

const path = require('path');
const dirs = [
    'build/Release',
    'build/Debug',
    'build',
    'out/Release',
    'out/Debug',
    'Release',
    'Debug',
    'build/default',
    'bin/winx64',
    'bin/winx86'
];

module.exports = undefined;

for (let dir of dirs) {
    try {
        module.exports = require(path.resolve(__dirname, dir, 'aiap-local-validator.node'));
        break;
    } catch { }
}

if (module.exports) {
    console.log('module.exports: ', module.exports);
} else {
    throw `Can't locate native 'aiap-local-validator.node' module in directories: ${dirs}`;
}
