
#ifndef PHP_WMERRORS_H
#define PHP_WMERRORS_H

extern zend_module_entry wmerrors_module_entry;
#define phpext_wmerrors_ptr &wmerrors_module_entry

#define PHP_WMERRORS_VERSION "2.0.0"

#ifdef PHP_WIN32
#define PHP_WMERRORS_API __declspec(dllexport)
#else
#define PHP_WMERRORS_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

#include "Zend/zend_smart_string_public.h"

PHP_MINIT_FUNCTION(wmerrors);
PHP_MSHUTDOWN_FUNCTION(wmerrors);
PHP_RINIT_FUNCTION(wmerrors);
PHP_RSHUTDOWN_FUNCTION(wmerrors);
PHP_MINFO_FUNCTION(wmerrors);

ZEND_BEGIN_MODULE_GLOBALS(wmerrors)
	char * message_file;
	char * error_script_file;
	char * log_file;
	char * log_line_prefix;
	int recursion_guard;
	zend_bool enabled;
	zend_bool log_backtrace;
	zend_bool ignore_logging_errors;
	zend_bool backtrace_in_php_error_message;
ZEND_END_MODULE_GLOBALS(wmerrors)


#ifdef ZTS
#define WMERRORS_G(v) TSRMG(wmerrors_globals_id, zend_wmerrors_globals *, v)
#else
#define WMERRORS_G(v) (wmerrors_globals.v)
#endif

#endif

