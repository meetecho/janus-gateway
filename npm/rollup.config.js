import replace from 'rollup-plugin-replace';
import * as fs from 'fs';

export default {
    name: 'Janus',
    input: 'module.js',
    output: {
        strict: false
    },
    plugins: [
        replace({
            JANUS_CODE: fs.readFileSync('../html/janus.js', 'utf-8'),
            delimiters: ['@','@'],
            includes: 'module.js'
        })
    ]
};
