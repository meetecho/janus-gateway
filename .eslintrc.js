module.exports = {
    "env": {
        "browser": true,
        "es6": true,
        "jquery": true
    },
    "extends": "eslint:recommended",
    "rules": {
        "no-console": "off",
        "no-empty": "off",
    },
    "globals": {
        "adapter": "readonly",
        "RTCRtpTransceiver": "readonly"
    }
};
