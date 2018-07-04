/*
 * Check: a unit test framework for C
 * Copyright (C) 2001, 2002 Arien Malec
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 */

#include <stdlib.h>
#include <stdint.h>
#include <check.h>

#include "../plugins/duktape-deps/duktape.h"
#include "../plugins/duktape-deps/duk_console.h"
#include "../plugins/duktape-deps/duk_module_duktape.h"

#include "../plugins/janus_duktape_extra_curl.h"

duk_context *duktape_ctx = NULL;


static duk_ret_t duktape_method_readfile(duk_context *ctx) {
  if(duk_get_type(ctx, 0) != DUK_TYPE_STRING) {
    return duk_throw(ctx);
  }

  const char *filename = duk_get_string(ctx, 0);
  char    *buffer;
  long    numbytes;

  FILE *f = fopen(filename, "r");

  fseek(f, 0L, SEEK_END);
  numbytes = ftell(f);

  fseek(f, 0L, SEEK_SET);
  buffer = (char*)calloc(numbytes, sizeof(char));	
  if(buffer == NULL)
    return 1;

  fread(buffer, sizeof(char), numbytes, f);
  fclose(f);


  if(f == NULL) {
    duk_push_string(ctx, "");
  } else {
    duk_push_lstring(ctx, buffer, numbytes);
  }

  free(buffer);

  return 1;
}



// test suite setup
void setup(void)
{

  duktape_ctx = duk_create_heap_default();
  duk_console_init(duktape_ctx, DUK_CONSOLE_PROXY_WRAPPER);
  duk_module_duktape_init(duktape_ctx);

  // hook curl in
  janus_duktape_register_extra_curl(duktape_ctx);

  // define module search path for tests
  duk_push_string(duktape_ctx, 
    "Duktape.modSearch = function (id, require, exports, module) {"\
    "  console.log('Loading module:', id, require, exports, module);"\
    "  var res = readFile(id + '.js');"\
    "  return res;"\
    "};"
  );
  duk_push_c_function(duktape_ctx, duktape_method_readfile, 1);
  duk_put_global_string(duktape_ctx, "readFile");

  if (duk_peval(duktape_ctx) != 0) {
      printf("Module eval failed: %s\n", duk_safe_to_string(duktape_ctx, -1));
  } else {
      printf("Module eval success: %s\n", duk_safe_to_string(duktape_ctx, -1));
  }


  printf("\n= test start =\n");
}

void teardown(void)
{
  duk_destroy_heap(duktape_ctx);
  duktape_ctx = NULL;
}

// module loads
START_TEST(test_duktape_extra_curl_loads)
{
  duk_push_string(duktape_ctx, 
    "var cases = require('./modules/test');"\
    "cases.test_duktape_extra_curl_loads();"
  );

  duk_peval(duktape_ctx);
  ck_assert_str_eq( "awesome" ,  duk_safe_to_string(duktape_ctx, -1) );

  duk_pop(duktape_ctx);
}
END_TEST

START_TEST(test_duktape_extra_curl_constructor_ignores_params)
{
  duk_push_string(duktape_ctx, 
    "var cases = require('./modules/test');"\
    "cases.test_duktape_extra_curl_constructor_ignores_params();"
  );

  duk_peval(duktape_ctx);
  ck_assert_str_eq( "[object Object]" ,  duk_safe_to_string(duktape_ctx, -1) );

  duk_pop(duktape_ctx);
}
END_TEST

START_TEST(test_duktape_extra_curl_success)
{
  duk_push_string(duktape_ctx, 
    "var cases = require('./modules/test');"\
    "cases.test_duktape_extra_curl_success();"
  );

  duk_peval(duktape_ctx);
  ck_assert_str_eq( "{\"code\":200,\"headers\":{},\"body\":\"<html><body></body></html>\"}",  duk_safe_to_string(duktape_ctx, -1) );

  duk_pop(duktape_ctx);
}
END_TEST

START_TEST(test_duktape_extra_curl_headers)
{
  duk_push_string(duktape_ctx, 
    "var cases = require('./modules/test');"\
    "cases.test_duktape_extra_curl_headers();"
  );

  duk_peval(duktape_ctx);
  ck_assert_str_eq( "{\"code\":200,\"headers\":{},\"body\":\"<html><body>foobar</body></html>\"}",  duk_safe_to_string(duktape_ctx, -1) );

  duk_pop(duktape_ctx);
}
END_TEST
  
START_TEST(test_duktape_extra_curl_post)
{
  duk_push_string(duktape_ctx, 
    "var cases = require('./modules/test');"\
    "cases.test_duktape_extra_curl_post();"
  );

  duk_peval(duktape_ctx);
  ck_assert_str_eq( "{\"foo\":\"bar\"}",  duk_safe_to_string(duktape_ctx, -1) );

  duk_pop(duktape_ctx);
}
END_TEST


Suite * suite(void)
{
    Suite *s;
    TCase *tc_core;
    TCase *tc_limits;

    s = suite_create("Extras");

    /* Core test case */
    tc_core = tcase_create("CURL");

    tcase_add_checked_fixture(tc_core, setup, teardown);
    tcase_add_test(tc_core, test_duktape_extra_curl_loads);
    tcase_add_test(tc_core, test_duktape_extra_curl_constructor_ignores_params);
    tcase_add_test(tc_core, test_duktape_extra_curl_success);
    tcase_add_test(tc_core, test_duktape_extra_curl_headers);
    tcase_add_test(tc_core, test_duktape_extra_curl_post);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
