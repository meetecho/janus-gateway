module.exports = {
    "env": {
        "browser": true,
        "es6": true
    },
    "extends": "eslint:recommended",
    "parserOptions": {
        "ecmaVersion": 2018
    },
    "rules": {
        "no-console": "off",
        "no-empty": "off",
    },
    "globals": {
        "adapter": "readonly",
        "jQuery": "readonly",
        "RTCRtpTransceiver": "readonly"
    }
};
