module.exports = {
    "env": {
        "browser": true,
        "es6": true,
        "jquery": true
    },
    "parserOptions": {
        "ecmaVersion": 2017
    },
    "extends": "eslint:recommended",
    "rules": {
        "no-console": "off",
        "no-empty": "off"
    },
    "globals": {
        "adapter": "readonly",
        "RTCRtpTransceiver": "readonly"
    }
};
