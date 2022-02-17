/*! \file   janus_duktape_extra.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus Duktape plugin extra hooks
 * \details  The Janus Duktape plugin implements all the mandatory hooks to
 * allow the C code to interact with a custom JavaScript script, and viceversa.
 * Anyway, JavaScript developers may want to have the C code do more than what
 * is provided out of the box, e.g., by exposing additional JavaScript methods
 * from C for further low level processing or native integration. This
 * "extra" implementation provides a mechanism to do just that, as
 * developers can just add their own custom hooks in the C extra code,
 * and the Duktape plugin will register the new methods along the stock ones.
 *
 * More specifically, the Janus Duktape plugin will always invoke the
 * janus_duktape_register_extra_functions() method when initializing. This
 * means that all developers will need to do to register a new function
 * is adding new \c duk_push_c_function calls to register their own functions
 * there, and they'll be added to the stack.
 *
 * \ingroup jspapi
 * \ref jspapi
 */

#include "janus_duktape_data.h"
#include "janus_duktape_extra.h"


/* Sample extra function we can register */
static duk_ret_t janus_duktape_extra_sample(duk_context *ctx) {
	/* Let's do nothing, and return 1234 */
	duk_push_int(ctx, 1234);
	return 1;
}

/* This is where you can add your custom extra functions */


/* Public method to register all custom extra functions */
void janus_duktape_register_extra_functions(duk_context *ctx) {
	if(ctx == NULL)
		return;
	JANUS_LOG(LOG_VERB, "Registering extra Duktape functions\n");
	/* Register all extra functions here */
	duk_push_c_function(ctx, janus_duktape_extra_sample, 0);
	duk_put_global_string(ctx, "testExtraFunction");
}
