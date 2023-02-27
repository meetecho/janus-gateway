// eslint-disable-next-line no-undef
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
		"no-empty": "off",
		"no-useless-escape": "off",
		"indent": [
			"warn",
			"tab",
			{
				"SwitchCase": 1
			}
		],
	},
	"globals": {
		/* WebRTC */
		"adapter": "readonly",
		"RTCRtpTransceiver": "readonly",
		"TransformStream": "readonly",
		/* bootstrap */
		"bootbox": "readonly",
		"Spinner": "readonly",
		"toastr": "readonly"
	}
};
