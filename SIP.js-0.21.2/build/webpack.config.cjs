var webpack = require('webpack');
var TerserPlugin = require('terser-webpack-plugin');
const CircularDependencyPlugin = require('circular-dependency-plugin')

var pkg = require('../package.json');
var year = new Date().getFullYear();
var banner = '\
\n\
 SIP version ' + pkg.version + '\n\
 Copyright (c) 2014-' + year + ' Junction Networks, Inc <http://www.onsip.com>\n\
 Homepage: https://sipjs.com\n\
 License: https://sipjs.com/license/\n\
\n\
\n\
 ~~~SIP.js contains substantial portions of JsSIP under the following license~~~\n\
 Homepage: http://jssip.net\n\
 Copyright (c) 2012-2013 José Luis Millán - Versatica <http://www.versatica.com>\n\
\n\
 Permission is hereby granted, free of charge, to any person obtaining\n\
 a copy of this software and associated documentation files (the\n\
 "Software"), to deal in the Software without restriction, including\n\
 without limitation the rights to use, copy, modify, merge, publish,\n\
 distribute, sublicense, and/or sell copies of the Software, and to\n\
 permit persons to whom the Software is furnished to do so, subject to\n\
 the following conditions:\n\
\n\
 The above copyright notice and this permission notice shall be\n\
 included in all copies or substantial portions of the Software.\n\
\n\
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,\n\
 EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF\n\
 MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND\n\
 NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE\n\
 LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION\n\
 OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION\n\
 WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.\n\
\n\
 ~~~ end JsSIP license ~~~\n\
\n\n\n';

module.exports = function (env) {
  var mode = env.buildType === 'min' ? 'production' : 'none';
  var mainDir = __dirname + '/../';

  var entry = {};
  entry['sip' + (env.buildType === 'min' ? '.min' : '')] = mainDir + '/src/index.ts';

  return {
    mode: mode,
    entry: entry,
    output: {
      path: mainDir + '/dist',
      filename: '[name].js',
      library: 'SIP',
      libraryTarget: 'umd',
      globalObject: 'this'
    },
    node: false,
    module: {
      rules: [
        {
          test: /\.ts$/,
          loader: "ts-loader",
          options: {
            compilerOptions: {
              "declaration": false,
              "declarationMap": false,
              "outDir": mainDir + "/dist"
            }
          }
        }
      ]
    },
    resolve: {
      extensions: ['.ts', '.d.ts', '.js'],
      extensionAlias: {
        '.js': ['.ts', '.js'],
        '.mjs': ['.mts', '.mjs']
      }
    },
    optimization: {
      minimizer: [
        new TerserPlugin({
          terserOptions: {
            output: {
              ascii_only: true
            }
          }
        })
      ]
    },
    plugins: [
      new CircularDependencyPlugin({
        // exclude detection of files based on a RegExp
        exclude: /a\.js|node_modules/,
        // add errors to webpack instead of warnings
        failOnError: true,
        // set the current working directory for displaying module paths
        cwd: process.cwd(),
      }),
      new webpack.BannerPlugin({
        banner: banner
      })
    ]
  };
}
