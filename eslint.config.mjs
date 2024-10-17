import globals from 'globals';
import js from '@eslint/js';
import html from 'eslint-plugin-html'

export default [
	{
		files: [
			'**/*.html',
			'**/*.js'
		],
		plugins: {
			html
		},
		languageOptions: {
			ecmaVersion: 'latest',
			globals: {
				...globals.browser,
				...globals.jquery,
				'adapter': 'readonly',
				'bootbox': 'readonly',
				'define': 'readonly',
				'module': 'readonly',
				'toastr': 'readonly',
			}
		},
		rules: {
			...js.configs.recommended.rules,
			'no-empty': 'off',
			'no-unused-vars': [
				'warn',
				{
					'args': 'all',
					'vars': 'all',
					'caughtErrors': 'all',
				}
			],
			'indent': [
				'error',
				'tab',
				{
					'SwitchCase': 1
				}
			],
		}
	}
];