/*! \file   janus_lua_extra.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus Lua plugin extra hooks
 * \details  The Janus Lua plugin implements all the mandatory hooks to
 * allow the C code to interact with a custom Lua script, and viceversa.
 * Anyway, Lua developers may want to have the C code do more than what
 * is provided out of the box, e.g., by exposing additional Lua methods
 * from C for further low level processing or native integration. This
 * "extra" implementation provides a mechanism to do just that, as
 * developers can just add their own custom hooks in the C extra code,
 * and the Lua plugin will register the new methods along the stock ones.
 *
 * More specifically, the Janus Lua plugin will always invoke the
 * janus_lua_register_extra_functions() method when initializing. This
 * means that all developers will need to do to register a new function
 * is adding new \c lua_register calls to register their own functions
 * there, and they'll be added to the stack.
 *
 * \ingroup luapapi
 * \ref luapapi
 */

#include "janus_lua_data.h"
#include "janus_lua_extra.h"


/* Sample extra function we can register */
static int janus_lua_extra_sample(lua_State *s) {
	/* Let's do nothing, and return 1234 */
	lua_pushnumber(s, 1234);
	return 1;
}

/* This is where you can add your custom extra functions */


/* Public method to register all custom extra functions */
void janus_lua_register_extra_functions(lua_State *state) {
	if(state == NULL)
		return;
	JANUS_LOG(LOG_VERB, "Registering extra Lua functions\n");
	/* Register all extra functions here */
	lua_register(state, "testExtraFunction", janus_lua_extra_sample);
}
