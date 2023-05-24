import strip from '@rollup/plugin-strip';
import replace from '@rollup/plugin-replace';
import { readFileSync } from 'fs';

export default {
    input: 'module.js',
    output: {
        strict: false
    },
    plugins: [
        replace({
            JANUS_CODE: readFileSync('../html/janus.js', 'utf-8'),
            delimiters: ['@','@'],
            includes: 'module.js',
            preventAssignment: true
        }),
        strip({
            labels: ['to_remove']
        })
    ]
};
