/*! \file   janus_duktape_extra.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus Duktape plugin extra hooks (headers)
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

#ifndef JANUS_DUKTAPE_EXTRA_H
#define JANUS_DUKTAPE_EXTRA_H

#include "duktape-deps/duktape.h"

/*! \brief Method to register extra JavaScript functions in the C code
 * @param[in] ctx The Duktape context to register the functions on */
void janus_duktape_register_extra_functions(duk_context *ctx);

#endif
