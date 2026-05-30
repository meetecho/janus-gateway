// Helpful name and version exports
import { LIBRARY_VERSION } from "./version.js";
const version = LIBRARY_VERSION;
const name = "sip.js";
export { name, version };

// Export api
export * from "./api/index.js";

// Export grammar
export * from "./grammar/index.js";

// Export namespaced core
import * as Core from "./core/index.js";
export { Core };

// Export namespaced web
import * as Web from "./platform/web/index.js";
export { Web };
