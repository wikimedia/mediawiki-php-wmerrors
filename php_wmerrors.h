
#ifndef PHP_WMERRORS_H
#define PHP_WMERRORS_H

extern zend_module_entry wmerrors_module_entry;
#define phpext_wmerrors_ptr &wmerrors_module_entry

#ifdef PHP_WIN32
#define PHP_WMERRORS_API __declspec(dllexport)
#else
#define PHP_WMERRORS_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

#include "ext/standard/php_smart_str_public.h"

#if _POSIX_C_SOURCE >= 200112 && !defined(ZTS)
#define WMERRORS_USE_TIMER
#include <signal.h>
#include <time.h>
#endif

PHP_MINIT_FUNCTION(wmerrors);
PHP_MSHUTDOWN_FUNCTION(wmerrors);
PHP_RINIT_FUNCTION(wmerrors);
PHP_RSHUTDOWN_FUNCTION(wmerrors);
PHP_MINFO_FUNCTION(wmerrors);

ZEND_BEGIN_MODULE_GLOBALS(wmerrors)
	char * message_file;
	char * log_file;
	char * log_line_prefix;
	int recursion_guard;
	int enabled;
	int log_backtrace;
	int ignore_logging_errors;
	int backtrace_in_php_error_message;
	long timeout;
	void (*old_on_timeout)(int seconds TSRMLS_DC);
#ifdef WMERRORS_USE_TIMER
	int timer_created;
	struct sigaction old_rt_action;
	timer_t timer;
#endif
	
ZEND_END_MODULE_GLOBALS(wmerrors)


#ifdef ZTS
#define WMERRORS_G(v) TSRMG(wmerrors_globals_id, zend_wmerrors_globals *, v)
#else
#define WMERRORS_G(v) (wmerrors_globals.v)
#endif

#endif

