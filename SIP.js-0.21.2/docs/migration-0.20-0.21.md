# Migration from 0.20.x to 0.21.x

## General

First off, the entire project was updated for ECMAScript module (ESM) support. Overall this makes the library more compatible and standard usages of the built library are backwards compatible (for example, if installing it via npm has been working for you it will continue to work). However if you are using a custom build or development process or fork of this library then this change may impact those processes. In particular, the TypeScript compilier options `module` and `moduleResolution` for this project have been changed to `NodeNext` for this project...
```
  "compilerOptions": {
    ...
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    ...
  },
```
... and as such all imports need to be fully specified going forward. For example, `import "../api";` now must be `import "../api/index.js";`. The changes to project which have been made in this regard include...

  - fully specified all imports
  - added .js extensions to all imports
  - changed compiler options to NodeNext
  - tweaked webpack configs (removed fullySpecified: false)

Secondly, the [SimpleUser](./simple-user.md) class has been ported from utilizing the API directly to using the [SessionManager](./session-manager.md) class (which is in turn is utilizing the API directly). The interface and usage of `SimpleUser` is completely identical (well, see below for the one breaking change), but if you were utilizing private methods, private properties, or otherwise depending on the internals of SimpleUser you may have issues.

Other changes:
 - new class `SessionManager` introduced (it's `SimpleUser` for multiple sessions)
 - exposed `iceGatheringComplete` method to support strategies other than the built in timeout
 - two minor breaking changes (see below)
 - minor bug fixes

## Two minor breaking changes

### 1. SimpleUser

The call signature for the `SimpleUser` `register` method has changed. It was...
```
register(registererOptions?: RegistererOptions, registererRegisterOptions?: RegistererRegisterOptions): Promise<void>;
```
and is now...
``` 
register(registererRegisterOptions?: RegistererRegisterOptions): Promise<void>;
```
Any `RegistererOptions` which were being passed as the first parameter to the `register` must now be provided to the constructor of `SimpleUser` along with any other options. For example...
```
const simpleUser = new SimpleUser(myServer, {
  registererOptions: {
    expires: 1800
  }
});
```
This change was made to fix the obviously incorrect call signature so that we did not further extend support for the problematic interface into the newly introduced `SessionManager`.

### 2. UserAgentOptions

The `autoStart` and `autoStop` options have been removed.

- `autoStart` was deprecated a long time ago and was removed to eliminate the side effect in the constructor.
- `autoStop` was removed to eliminate the `UserAgent` dependency a web browser.

If you want the `autoStart` behavior going forward, you can implement it by calling `start` in your code immediately after construction as follows...

```
// Construct the UserAgent
userAgent = new UserAgent(/* options */);

// Call start
userAgent.start();
```

If you want the `autoStop` behavior going forward, you can implement it by adding a listener to your code as follows...

```
// Construct the UserAgent
userAgent = new UserAgent(/* options */);

// Add a listener to "auto stop" on page unload 
window.addEventListener("unload", () => userAgent.stop());
```
