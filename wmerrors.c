
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_wmerrors.h"
#include "php_streams.h" /* for __php_stream_call_depth */
#include "SAPI.h" /* for sapi_module */
#include "ext/standard/file.h" /* for file_globals aka. FG() */
#include "ext/date/php_date.h" /* for php_format_date */
#include "ext/standard/php_smart_str.h" /* for smart_str */
#include "ext/standard/html.h" /* for php_escape_html_entities */
#include "Zend/zend_builtin_functions.h" /* for zend_fetch_debug_backtrace */

void wmerrors_cb(int type, const char *error_filename, const uint error_lineno, const char *format, va_list args);
static void wmerrors_show_message(int type, const char *error_filename, const uint error_lineno, const char *format, va_list args TSRMLS_DC);


ZEND_DECLARE_MODULE_GLOBALS(wmerrors)

zend_function_entry wmerrors_functions[] = {
	{NULL, NULL, NULL}
};


zend_module_entry wmerrors_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	"wmerrors",
	wmerrors_functions,
	PHP_MINIT(wmerrors),
	PHP_MSHUTDOWN(wmerrors),
	PHP_RINIT(wmerrors),	
	PHP_RSHUTDOWN(wmerrors),
	PHP_MINFO(wmerrors),
#if ZEND_MODULE_API_NO >= 20010901
	"0.2",
#endif
	STANDARD_MODULE_PROPERTIES
};


#ifdef COMPILE_DL_WMERRORS
ZEND_GET_MODULE(wmerrors)
#endif

PHP_INI_BEGIN()
	STD_PHP_INI_BOOLEAN("wmerrors.enabled", "0", PHP_INI_ALL, OnUpdateBool, enabled, zend_wmerrors_globals, wmerrors_globals )
	STD_PHP_INI_ENTRY("wmerrors.message_file", "", PHP_INI_ALL, OnUpdateString, message_file, zend_wmerrors_globals, wmerrors_globals)
	STD_PHP_INI_ENTRY("wmerrors.logging_file", "", PHP_INI_ALL, OnUpdateString, logging_file, zend_wmerrors_globals, wmerrors_globals)
	STD_PHP_INI_ENTRY("wmerrors.log_level", "0", PHP_INI_ALL, OnUpdateLong, log_level, zend_wmerrors_globals, wmerrors_globals)
PHP_INI_END()

void (*old_error_cb)(int type, const char *error_filename, const uint error_lineno, const char *format, va_list args);

static void php_wmerrors_init_globals(zend_wmerrors_globals *wmerrors_globals)
{
	wmerrors_globals->message_file = NULL;
	wmerrors_globals->logging_file = NULL;
	wmerrors_globals->log_level = 0;
	wmerrors_globals->log_buffer.c = NULL;
}

PHP_MINIT_FUNCTION(wmerrors)
{
	ZEND_INIT_MODULE_GLOBALS(wmerrors, php_wmerrors_init_globals, NULL);
	REGISTER_INI_ENTRIES();	
	old_error_cb = zend_error_cb;
	zend_error_cb = wmerrors_cb;
	return SUCCESS;
}


PHP_MSHUTDOWN_FUNCTION(wmerrors)
{
	UNREGISTER_INI_ENTRIES();
	zend_error_cb = old_error_cb;
	return SUCCESS;
}



PHP_RINIT_FUNCTION(wmerrors)
{
	WMERRORS_G(recursion_guard) = 0;
	return SUCCESS;
}



PHP_RSHUTDOWN_FUNCTION(wmerrors)
{
	return SUCCESS;
}

PHP_MINFO_FUNCTION(wmerrors)
{
	php_info_print_table_start();
	php_info_print_table_row(2, "Custom fatal error pages", "enabled");
	php_info_print_table_end();
	DISPLAY_INI_ENTRIES();
}

/* error_handling moved in March 2008 on the PHP 5.3 branch */
#if ZEND_MODULE_API_NO >= 20090115
#define WM_ERROR_HANDLING EG(error_handling)
#else
#define WM_ERROR_HANDLING PG(error_handling)
#endif

static const char* error_type_to_string(int type);
static void wmerrors_log_error(int type, const char *error_filename, const uint error_lineno, const char *format, va_list args TSRMLS_DC);

void wmerrors_cb(int type, const char *error_filename, const uint error_lineno, const char *format, va_list args)
{
	TSRMLS_FETCH();
	
	/* Do not call the custom error handling if:
	 * it's not enabled,
	 * OR the error is not one of E_{,CORE_,COMPILE_,USER_,RECOVERABLE_}ERROR,
	 * OR the error is an E_RECOVERABLE_ERROR and is being thrown as an exception,
	 * OR it's triggering itself (recursion guard)
	 */	
	if ( !WMERRORS_G(enabled)
			|| (type == E_RECOVERABLE_ERROR && WM_ERROR_HANDLING == EH_THROW && !EG(exception))
			|| (type != E_ERROR && type != E_CORE_ERROR && type != E_COMPILE_ERROR 
			      && type != E_USER_ERROR && type != E_RECOVERABLE_ERROR)
			|| WMERRORS_G(recursion_guard))
	{
		old_error_cb(type, error_filename, error_lineno, format, args);
		return;
	}
	WMERRORS_G(recursion_guard) = 1;
	/* No more OOM errors for now thanks */
	zend_set_memory_limit((size_t)-1);

	/* Do not show the html error to console */
	if ( WMERRORS_G(enabled) && strncmp(sapi_module.name, "cli", 3) ) {
		/* Show the message */
		wmerrors_show_message(type, error_filename, error_lineno, format, args TSRMLS_CC);
	}

	if ( WMERRORS_G(enabled) && WMERRORS_G(log_level) ) {
		/* Log the error */
		wmerrors_log_error(type, error_filename, error_lineno, format, args TSRMLS_CC);
	}

	WMERRORS_G(recursion_guard) = 0;
	zend_set_memory_limit(PG(memory_limit));

	/* Pass through */
	old_error_cb(type, error_filename, error_lineno, format, args);
}

static php_stream * open_logging_file(const char* stream_name) {
	php_stream * stream;
	int err; char *errstr = NULL;
	struct timeval tv;
	
	if ( strncmp( stream_name, "tcp://", 6 ) && strncmp( stream_name, "udp://", 6 ) ) {
		/* Is it a wrapper? */
		stream = php_stream_open_wrapper(stream_name, "ab", ENFORCE_SAFE_MODE | REPORT_ERRORS, NULL);
	} else {
		/* Maybe it's a transport? */
		double timeout = FG(default_socket_timeout);
		unsigned long conv;
		conv = (unsigned long) (timeout * 1000000.0);
		tv.tv_sec = conv / 1000000;
		tv.tv_usec = conv % 1000000;
		
		stream = php_stream_xport_create(stream_name, strlen(stream_name), ENFORCE_SAFE_MODE | REPORT_ERRORS,
			STREAM_XPORT_CLIENT | STREAM_XPORT_CONNECT, NULL, &tv, NULL, &errstr, &err);
	}
		
	return stream;
}

/* Callback for zend_print_zval_r_ex()
 * Writes to the global buffer
 */
static int wmerrors_write_trace(const char *str, uint str_length) {
	TSRMLS_FETCH();
	smart_str_appendl(&WMERRORS_G(log_buffer), str, str_length);
	return str_length;
}

static void wmerrors_log_error(int type, const char *error_filename, const uint error_lineno, const char *format, va_list args TSRMLS_DC) {
	char *tmp1; zval *trace; char *error_time_str;
	int tmp1_len; va_list my_args;
	php_stream *logfile_stream;
	
	if ( !WMERRORS_G(enabled) || !WMERRORS_G(log_level) ) {
		/* Redundant with the caller */
		return;
	}
	
	if ( !WMERRORS_G(logging_file) || *WMERRORS_G(logging_file) == '\0') {
		/* No log file configured */
		return;
	}
	
	/* Try opening the logging file */
	logfile_stream = open_logging_file( WMERRORS_G(logging_file) );
	if ( !logfile_stream ) {
		return;
	}
	
	/* Don't destroy the caller's va_list */
	va_copy(my_args, args);
	tmp1_len = vspprintf(&tmp1, 0, format, my_args);
	va_end(my_args);
	
	/* Log the error (log_level >= 1) */
	error_time_str = php_format_date("d-M-Y H:i:s", 11, time(NULL), 0 TSRMLS_CC);
	php_stream_printf(logfile_stream TSRMLS_CC, "[%s UTC] %s: %.*s at %s on line %u%s", error_time_str, error_type_to_string(type), tmp1_len, tmp1, error_filename, error_lineno, PHP_EOL);
	efree(error_time_str);
	efree(tmp1);
	
	/* Write a backtrace */
	if ( WMERRORS_G(log_level) >= 2 ) {
		ALLOC_INIT_ZVAL(trace);
		zend_fetch_debug_backtrace(trace, 0, 0 TSRMLS_CC);
		zend_print_zval_r_ex(wmerrors_write_trace, trace, 4 TSRMLS_CC);
		FREE_ZVAL(trace);
		php_stream_write(logfile_stream, WMERRORS_G(log_buffer).c, WMERRORS_G(log_buffer).len TSRMLS_CC);
	}
	
	php_stream_close( logfile_stream );
}

static void wmerrors_show_message(int type, const char *error_filename, const uint error_lineno, const char *format, va_list args TSRMLS_DC)
{
	php_stream *stream;
	char *message, *p;
	int message_len;
	long maxlen = PHP_STREAM_COPY_ALL;
	char * tmp1, *tmp2;
	int tmp1_len, tmp2_len;
	smart_str expanded = {0};
	va_list my_args;

	/* Is there a sane message_file? */
	if (!WMERRORS_G(message_file) || *WMERRORS_G(message_file) == '\0') {
		return;
	}

	/* Open it */
	stream = php_stream_open_wrapper(WMERRORS_G(message_file), "rb", 
			ENFORCE_SAFE_MODE | REPORT_ERRORS, NULL);
	if (!stream) {
		return;
	}
	
	/* Don't destroy the caller's va_list */
	va_copy(my_args, args);

	/* Read the contents */
	message_len = php_stream_copy_to_mem(stream, &message, maxlen, 0);
	php_stream_close(stream);

	/* Replace some tokens */
	for (p = message; p < message + message_len; p++) { 
		if (*p == '$') {
			if (!strncmp(p, "$file", sizeof("$file")-1)) {
				tmp1 = php_escape_html_entities((unsigned char*)error_filename, 
						strlen(error_filename), &tmp1_len, 0, ENT_COMPAT, NULL TSRMLS_CC);
				smart_str_appendl(&expanded, tmp1, tmp1_len);
				efree(tmp1);
				p += sizeof("file") - 1;
			} else if (!strncmp(p, "$line", sizeof("$line")-1)) {
				tmp1_len = spprintf(&tmp1, 0, "%u", error_lineno);
				smart_str_appendl(&expanded, tmp1, tmp1_len);
				efree(tmp1);
				p += sizeof("line") - 1;
			} else if (!strncmp(p, "$message", sizeof("$message")-1)) {
				/* Don't destroy args */
				tmp1_len = vspprintf(&tmp1, 0, format, my_args);
				tmp2 = php_escape_html_entities((unsigned char*)tmp1, tmp1_len, &tmp2_len, 
						0, ENT_COMPAT, NULL TSRMLS_CC);
				smart_str_appendl(&expanded, tmp2, tmp2_len);
				efree(tmp1);
				efree(tmp2);
				p += sizeof("message") - 1;
			} else {
				smart_str_appendc(&expanded, '$');
			}
		} else {
			smart_str_appendc(&expanded, *p);
		}
	}

	/* Set headers */
	if (!SG(headers_sent)) {
		sapi_header_line ctr = {0};

		ctr.line = "HTTP/1.0 500 Internal Server Error";
		ctr.line_len = strlen(ctr.line);
		sapi_header_op(SAPI_HEADER_REPLACE, &ctr TSRMLS_CC);
	}

	/* Write the message out */
	if (expanded.c) {
		php_write(expanded.c, expanded.len TSRMLS_CC);
	}
	
	/* Clean up */
	smart_str_free(&expanded);
	efree(message);
	va_end(my_args);
}

static const char* error_type_to_string(int type) {
	int i;
	#define ErrorType(x) {x, #x}
	static struct { int type; const char* name; } error_names[] = {
		ErrorType(E_ERROR),
		ErrorType(E_CORE_ERROR),
		ErrorType(E_COMPILE_ERROR),
		ErrorType(E_USER_ERROR),
		ErrorType(E_RECOVERABLE_ERROR),
		ErrorType(E_WARNING),
		ErrorType(E_CORE_WARNING),
		ErrorType(E_COMPILE_WARNING),
		ErrorType(E_USER_WARNING),
		ErrorType(E_PARSE),
		ErrorType(E_NOTICE),
		ErrorType(E_USER_NOTICE),
		ErrorType(E_STRICT),
		ErrorType(E_DEPRECATED),
		ErrorType(E_USER_DEPRECATED)
	};
	
	for (i=0; i < sizeof(error_names)/sizeof(error_names[0]); i++) {
		if (type == error_names[i].type) {
			return error_names[i].name;
		}
	}
	return "Unknown error";
}
