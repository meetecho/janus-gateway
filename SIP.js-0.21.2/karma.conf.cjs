module.exports = function(config) {
  config.set({

    // base path that will be used to resolve all patterns (eg. files, exclude)
    basePath: '',

    // frameworks to use
    // available frameworks: https://npmjs.org/browse/keyword/karma-adapter
    frameworks: ['jasmine', 'webpack'],

    // list of files / patterns to load in the browser
    files: [
      'test/spec/**/*.js',
    ],

    // list of files to exclude
    exclude: [],

    // preprocess matching files before serving them to the browser
    // available preprocessors: https://npmjs.org/browse/keyword/karma-preprocessor
    preprocessors: {
      'test/spec/**/*.js': ['webpack', 'sourcemap']
    },

    webpack: {
      devtool: 'inline-source-map',
      mode: 'production'
    },

    // test results reporter to use
    // possible values: 'dots', 'progress'
    // available reporters: https://npmjs.org/browse/keyword/karma-reporter
    reporters: [],

    // web server port
    port: 9876,

    // enable / disable colors in the output (reporters and logs)
    colors: true,

    // level of logging
    // possible values: config.LOG_DISABLE || config.LOG_ERROR || config.LOG_WARN || config.LOG_INFO || config.LOG_DEBUG
    logLevel: config.LOG_INFO,

    // enable / disable watching file and executing tests whenever any file changes
    autoWatch: false,

    // you can define custom flags
    customLaunchers: {
      // --use-fake-ui-for-media-stream avoids the need to grant camera/microphone permissions.
      // --use-fake-device-for-media-stream feeds a test pattern to getUserMedia() instead of live camera input.
      ChromeHeadlessFakeMediaStream: {
        base: 'ChromeHeadless',
        flags: ['--use-fake-ui-for-media-stream', '--use-fake-device-for-media-stream']
      }
    },

    // start these browsers
    // available browser launchers: https://npmjs.org/browse/keyword/karma-launcher
    browsers: [],

    // Continuous Integration mode
    // if true, Karma captures browsers, runs the tests and exits
    //singleRun: true,

    client: {
      clearContext: false,
      captureConsole: false,
      jasmine: {
        timeoutInterval: 10000,
        // only necessary due to potential bug in SpecSanityCheck 8.2.2.2, running
        // those out of order causes them to fail
        random: false
      }
    },

    // Concurrency level
    // how many browser should be started simultaneous
    concurrency: Infinity,

    plugins : [
      'karma-chrome-launcher',
      'karma-jasmine',
      'karma-jasmine-html-reporter',
      'karma-mocha-reporter',
      'karma-webpack',
      'karma-sourcemap-loader'
    ]
  })
}
