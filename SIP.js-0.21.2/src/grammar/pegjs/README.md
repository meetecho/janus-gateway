## SIP Parser Grammar

SIP,js uses [PEG.js](https://github.com/dmajda/pegjs) to build its parser grammar, a PEG based parser generator for JavaScript.

The grammar source is defined in PEG format in `src/Grammar.pegjs` file. It must be converted to JavaScript by using PEG.js

### Compiling SIP Grammar

`npm run build` in the SIP.js root directory
