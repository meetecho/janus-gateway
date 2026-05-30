# Migration from 0.14.x to 0.15.x

The 0.15.x release is a backwards compatible drop-in replacement for 0.14.x.

The 0.15.x release introduces a "new" API and deprecates the "legacy" API in 0.14.x.

The 0.15.x release is intended to facilitate migration from the legacy API to the new API.

The 0.15.x release contains both the new API and the legacy API, but the two are not compatible. That is, you may use one or the other but cannot "mix" the usage of the two. For example, a `Session` created with the legacy API is not compatible with a `Session` in the new API.

The legacy API will be removed in 0.16.x in favor of the new API.
