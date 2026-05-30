# How to version release SIP.js

On `main` branch...

## Development Dependencies

Prior to making a release, consider updating out of date dependencies.

* `npm outdated`
* `npm update --save`

Note that the source code itself has no dependencies.
A lot of work has been done to make it that way, so please keep it that way.

## Clean, Build and Test

Make sure it builds and the tests pass from a clean checkout.

* `git clean -xdf .`
* `npm i`
* `npm run build-and-test`

All tests must pass.

* `npm run build-demo`

All the demos must work.

## Documentation

Make sure the documentation is up to date and review any changes to the API. Commit any new documentation and consider the version number bump based on the changes to the API. If you commit any changes, go back to the Clean, Build and Test step.

* `npm run build-docs`

## Version

DO NOT MANUALLY UPDATE THE VERSION NUMBERS.

We hardcode the version in the library, using npm version will update it appropriately.

* `npm version <major.minor.patch> --git-tag-version false`

The updated files must be commited with a message "Version <major.minor.patch>".

## Before Publishing: Make Sure Your Package Installs and Works

This is important.

If you can not install it locally, you'll have problems trying to publish it. Or, worse yet, you'll be able to publish it, but you'll be publishing a broken or pointless package. So don't do that.

This approach will leverage the `npm pack` command to package up and zip your npm package into a single file (`<package-name>.tgz`), the same way it does for publishing. You can double check that your package will include only the files you intend it to when published and you can go to the project you want to use the package in and install it via this file. The steps to do this are as follows:

1. From within your npm package directory, run `npm pack` in your terminal. Note the .tgz file it produces and the location of it.
2. Change directories to the project directory where you want to use the npm package. Example: `cd /path/to/project`
3. From within the client project directory, run `npm install /path/to/package.tgz` but replace it with the proper path to the location of the .tgz file from step 1.
4. Then you can start using the package in that client project to test things out. This will give you the closest to production experience for using your npm package.
5. Delete the .tgz file created in step 1.

## Tag, Push and Publish

* `git tag <major.minor.patch>`
* `git push`
* `git push --tags`
* `npm publish`

### Sigh, don’t use .npmignore

Instead whitelist files in `package.json`. It's better to be exact about what we want in than to be forgetting to add what we want out.

```
  "main": "./lib/index.js",
  "files": [
    "/lib"
  ],
```

## Update release notes on GitHub

Build the bundle files to upload.

`npm run build-bundles`

* Find 'Releases' on repository page
* Draft and publish release notes for new tag
* Upload bundles for new verison

