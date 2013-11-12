
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#include "php.h"
#include "php_ini.h"
#include "php_wmerrors.h"
#include "ext/standard/php_standard.h"
#include "SAPI.h" /* for sapi_module */
#include "ext/date/php_date.h" /* for php_format_date */
#include "ext/standard/php_smart_str.h" /* for smart_str */
#include "Zend/zend_builtin_functions.h" /* for zend_fetch_debug_backtrace */

static int wmerrors_post_deactivate();
static void wmerrors_cb(int type, const char *error_filename, const uint error_lineno, const char *format, va_list args);
static void wmerrors_show_message(int type, const char *error_filename, const uint error_lineno, const char *format, va_list args TSRMLS_DC);
static void wmerrors_get_concise_backtrace(smart_str *s TSRMLS_DC);
static void wmerrors_write_full_backtrace(smart_str *s TSRMLS_DC);
static void wmerrors_write_request_info(smart_str *s TSRMLS_DC);
static void wmerrors_alarm_handler(int signo);
static void wmerrors_create_timer(TSRMLS_D);
static void wmerrors_destroy_timer(TSRMLS_D);
static void wmerrors_start_timer(TSRMLS_D);

ZEND_DECLARE_MODULE_GLOBALS(wmerrors)

PHP_FUNCTION(wmerrors_malloc_test);

ZEND_BEGIN_ARG_INFO(wmerrors_malloc_test_arginfo, 0)
ZEND_END_ARG_INFO()

zend_function_entry wmerrors_functions[] = {
	PHP_FE(wmerrors_malloc_test, wmerrors_malloc_test_arginfo)
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
	"1.1.2",
#endif
	NO_MODULE_GLOBALS,
	wmerrors_post_deactivate,
	STANDARD_MODULE_PROPERTIES_EX
};


#ifdef COMPILE_DL_WMERRORS
ZEND_GET_MODULE(wmerrors)
#endif

PHP_INI_BEGIN()
	STD_PHP_INI_BOOLEAN("wmerrors.enabled", "0", PHP_INI_ALL, OnUpdateBool, enabled, zend_wmerrors_globals, wmerrors_globals )
	STD_PHP_INI_ENTRY("wmerrors.message_file", "", PHP_INI_ALL, OnUpdateString, message_file, zend_wmerrors_globals, wmerrors_globals)
	STD_PHP_INI_ENTRY("wmerrors.log_file", "", PHP_INI_ALL, OnUpdateString, log_file, zend_wmerrors_globals, wmerrors_globals)
	STD_PHP_INI_BOOLEAN("wmerrors.log_backtrace", "0", PHP_INI_ALL, OnUpdateBool, log_backtrace, zend_wmerrors_globals, wmerrors_globals)
	STD_PHP_INI_ENTRY("wmerrors.log_line_prefix", "", PHP_INI_ALL, OnUpdateString, log_line_prefix, zend_wmerrors_globals, wmerrors_globals)
	STD_PHP_INI_BOOLEAN("wmerrors.ignore_logging_errors", "0", PHP_INI_ALL, OnUpdateBool, ignore_logging_errors, zend_wmerrors_globals, wmerrors_globals)
	STD_PHP_INI_BOOLEAN("wmerrors.backtrace_in_php_error_message", "0", PHP_INI_ALL, OnUpdateBool, backtrace_in_php_error_message, zend_wmerrors_globals, wmerrors_globals)
	STD_PHP_INI_ENTRY("wmerrors.timeout", "10", PHP_INI_ALL, OnUpdateLong, timeout, zend_wmerrors_globals, wmerrors_globals)
PHP_INI_END()

void (*old_error_cb)(int type, const char *error_filename, const uint error_lineno, const char *format, va_list args);

static void php_wmerrors_init_globals(zend_wmerrors_globals *wmerrors_globals)
{
	wmerrors_globals->message_file = NULL;
	wmerrors_globals->log_file = NULL;
	wmerrors_globals->log_backtrace = 0;
	wmerrors_globals->log_line_prefix = NULL;
#ifdef WMERRORS_USE_TIMER
	wmerrors_globals->timer_created = 0;
#endif
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
	wmerrors_create_timer(TSRMLS_C);
	return SUCCESS;
}



PHP_RSHUTDOWN_FUNCTION(wmerrors)
{
	return SUCCESS;
}

int wmerrors_post_deactivate()
{
	TSRMLS_FETCH();
	wmerrors_destroy_timer(TSRMLS_C);
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

static const char* wmerrors_error_type_to_string(int type);
static void wmerrors_log_error(int type, const char *error_filename, const uint error_lineno, const char *format, va_list args TSRMLS_DC);

static void wmerrors_cb(int type, const char *error_filename, const uint error_lineno, const char *format, va_list args)
{
	smart_str new_filename = { NULL };
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
		/* recursion_guard != 1 means this is an error in writing to the log file.
		 * Ignore it if configured to do so.
		 */
		if (WMERRORS_G(recursion_guard) == 1 || !WMERRORS_G(ignore_logging_errors))
			old_error_cb(type, error_filename, error_lineno, format, args);
		return;
	}
	WMERRORS_G(recursion_guard) = 1;
	/* No more OOM errors for now thanks */
	zend_set_memory_limit((size_t)-1);

	if (WMERRORS_G(timeout)) {
		wmerrors_start_timer(TSRMLS_C);
	}

	/* Do not show the html error to console */
	if ( WMERRORS_G(enabled) && strncmp(sapi_module.name, "cli", 3) ) {
		/* Show the message */
		wmerrors_show_message(type, error_filename, error_lineno, format, args TSRMLS_CC);
	}

	if ( WMERRORS_G(enabled) ) {
		/* Log the error */
		wmerrors_log_error(type, error_filename, error_lineno, format, args TSRMLS_CC);
	}
	
	/* Put a concise backtrace in the normal output */
	if (WMERRORS_G(backtrace_in_php_error_message)) {
		wmerrors_get_concise_backtrace(&new_filename TSRMLS_CC);
	}
	smart_str_appendl(&new_filename, error_filename, strlen(error_filename));
	smart_str_0(&new_filename);

	WMERRORS_G(recursion_guard) = 0;
	zend_set_memory_limit(PG(memory_limit));

#ifndef ZTS
	if (PG(connection_status) & PHP_CONNECTION_TIMEOUT) {
		/* abort instead of deadlocking */
		const char abort_message[] = "wmerrors: doing precautionary abort() after request timeout\n";
		write(STDERR_FILENO, abort_message, sizeof(abort_message) - 1);
		abort();
	}
#endif

	/* Pass through */
	old_error_cb(type, new_filename.c, error_lineno, format, args);
	
	/* Note: old_error_cb() may not return, in which case there will be no 
	 * explicit free of new_filename */
	smart_str_free(&new_filename);
}

/* Obtain a concisely formatted backtrace */
static void wmerrors_get_concise_backtrace(smart_str *s TSRMLS_DC) {
	zval *trace, **entry, **file, **line, *line_copy;
	HashPosition pos;
	char *basename;
	size_t basename_len;
	int use_copy;
	
	ALLOC_INIT_ZVAL(trace);
	/* Argument added April 2011 6f3148db */
#if PHP_VERSION_ID < 50399
	zend_fetch_debug_backtrace(trace, 0, 0 TSRMLS_CC);
#else
	zend_fetch_debug_backtrace(trace, 0, 0, 1000 TSRMLS_CC);
#endif
	
	if (Z_TYPE_P(trace) != IS_ARRAY) {
		/* Not supposed to happen */
		zval_dtor(trace);
		FREE_ZVAL(trace);
		return;
	}
	
	zend_hash_internal_pointer_reset_ex(Z_ARRVAL_P(trace), &pos);
	while (zend_hash_get_current_data_ex(Z_ARRVAL_P(trace), (void **)&entry, &pos) == SUCCESS) {
		if (!entry || !*entry || Z_TYPE_PP(entry) != IS_ARRAY) {
			/* Not supposed to happen */
			smart_str_appendl(s, "?!? ", sizeof("?!? "));
			zend_hash_move_forward_ex(Z_ARRVAL_P(trace), &pos);
			continue;
		}
		
		zend_hash_find(Z_ARRVAL_PP(entry), "file", sizeof("file"), (void **)&file);
		zend_hash_find(Z_ARRVAL_PP(entry), "line", sizeof("line"), (void **)&line);
		
		if(!file || !*file || Z_TYPE_PP(file) != IS_STRING || !line || !*line || Z_TYPE_PP(line) != IS_LONG) {
			/* Not supposed to happen */
			smart_str_appendl(s, "?!?!? ", sizeof("?!?!? "));
			zend_hash_move_forward_ex(Z_ARRVAL_P(trace), &pos);
			continue;
		}
		php_basename(Z_STRVAL_PP(file), Z_STRLEN_PP(file), NULL, 0, &basename, &basename_len TSRMLS_CC);
		ALLOC_INIT_ZVAL(line_copy);
		zend_make_printable_zval(*line, line_copy, &use_copy);
		smart_str_appendl(s, basename, basename_len);
		smart_str_appendc(s, ':');
		smart_str_appendl(s, Z_STRVAL_P((use_copy ? line_copy : *line)), Z_STRLEN_P((use_copy ? line_copy : *line)));
		smart_str_appendc(s, ' ');
		
		efree(basename);
		zval_dtor(line_copy);
		FREE_ZVAL(line_copy);
		zend_hash_move_forward_ex(Z_ARRVAL_P(trace), &pos);
	}
	zval_dtor(trace);
	FREE_ZVAL(trace);
}

static php_stream * wmerrors_open_log_file(const char* stream_name TSRMLS_DC) {
	php_stream * stream;
	int err; char *errstr = NULL;
	struct timeval tv;
	int flags = ENFORCE_SAFE_MODE;
	
	if (!WMERRORS_G(ignore_logging_errors))
		flags |= REPORT_ERRORS;
	
	if ( strncmp( stream_name, "tcp://", 6 ) && strncmp( stream_name, "udp://", 6 ) ) {
		/* Is it a wrapper? */
		stream = php_stream_open_wrapper((char*)stream_name, "ab", flags, NULL);
	} else {
		/* Maybe it's a transport? */
		double timeout = FG(default_socket_timeout);
		unsigned long conv;
		conv = (unsigned long) (timeout * 1000000.0);
		tv.tv_sec = conv / 1000000;
		tv.tv_usec = conv % 1000000;
		
		stream = php_stream_xport_create(stream_name, strlen(stream_name), flags,
			STREAM_XPORT_CLIENT | STREAM_XPORT_CONNECT, NULL, &tv, NULL, &errstr, &err);
	}

	/* Set the chunk size to something fairly large, to avoid fragmentation */
	if (stream) {
		php_stream_set_option(stream, PHP_STREAM_OPTION_SET_CHUNK_SIZE, 65507, NULL);
	}
	return stream;
}

static void wmerrors_log_error(int type, const char *error_filename, const uint error_lineno, const char *format, va_list args TSRMLS_DC) {
	char *input_message, *first_line;
	int input_message_len, first_line_len;
	char error_time_str[256];
	time_t simpleTime;
	struct tm brokenTime;
	va_list my_args;
	php_stream *logfile_stream;
	smart_str message = {NULL};
	smart_str prefixed_message = {NULL};
	
	if ( !WMERRORS_G(enabled) ) {
		/* Redundant with the caller */
		return;
	}
	
	if ( !WMERRORS_G(log_file) || *WMERRORS_G(log_file) == '\0') {
		/* No log file configured */
		return;
	}
	
	/* Try opening the logging file */
	/* Set recursion_guard==2 whenever we're doing something to the log file */
	WMERRORS_G(recursion_guard) = 2;
	logfile_stream = wmerrors_open_log_file(WMERRORS_G(log_file) TSRMLS_CC);
	WMERRORS_G(recursion_guard) = 1;
	if ( !logfile_stream ) {
		return;
	}
	
	/* Don't destroy the caller's va_list */
	va_copy(my_args, args);
	/* Write the input message */
	input_message_len = vspprintf(&input_message, 0, format, my_args);
	va_end(my_args);
	
	/* Get a date string */
	simpleTime = time(NULL);
	localtime_r(&simpleTime, &brokenTime);
	strftime(error_time_str, sizeof(error_time_str), "%Y-%m-%d %H:%M:%S", &brokenTime);

	/* Make the initial log line */
	first_line_len = spprintf(&first_line, 0, "[%s] %s: %.*s at %s on line %u%s", 
			error_time_str, wmerrors_error_type_to_string(type), 
			input_message_len, input_message, error_filename, 
			error_lineno, PHP_EOL);
	smart_str_appendl(&message, first_line, first_line_len);
	efree(input_message);
	efree(first_line);
	
	/* Write the request info */
	wmerrors_write_request_info(&message TSRMLS_CC);

	/* Write a backtrace */
	if ( WMERRORS_G(log_backtrace) ) {
		smart_str_appends(&message, "Backtrace:");
		smart_str_appends(&message, PHP_EOL);
		wmerrors_write_full_backtrace(&message TSRMLS_CC);
	}

	/* Add the log line prefix if requested */
	if (message.c && WMERRORS_G(log_line_prefix) && WMERRORS_G(log_line_prefix)[0]) {
		char * line_start = message.c;
		char * message_end = message.c + message.len;
		char * line_end;
		while (line_start < message_end) {
			smart_str_appends(&prefixed_message, WMERRORS_G(log_line_prefix));
			line_end = memchr(line_start, '\n', message_end - line_start);
			if (!line_end) {
				line_end = message_end - 1;
			}
			smart_str_appendl(&prefixed_message, line_start, line_end - line_start + 1);
			line_start = line_end + 1;
		}
		smart_str_free(&message);
	} else {
		prefixed_message = message;
	}

	WMERRORS_G(recursion_guard) = 2;
	if (prefixed_message.c) {
		php_stream_write(logfile_stream, prefixed_message.c, prefixed_message.len);
	}
	php_stream_close(logfile_stream);
	WMERRORS_G(recursion_guard) = 1;
	smart_str_free(&prefixed_message);
}


/**
 * Write a backtrace to a stream
 */
static void wmerrors_write_full_backtrace(smart_str * s TSRMLS_DC) {
	zval *trace = NULL;
	zval backtrace_fname;
	int status;
	zend_class_entry * exception_class;
	zval *exception;

	/* Create an Exception object */
	exception_class = zend_fetch_class("Exception", sizeof("Exception") - 1, 
		ZEND_FETCH_CLASS_DEFAULT TSRMLS_CC);
	if (!exception_class) {
		return;
	}
	MAKE_STD_ZVAL(exception);
	object_init_ex(exception, exception_class);

	/* Call Exception::getTraceAsString() */
	ZVAL_STRING(&backtrace_fname, "getTraceAsString", 1);
	status = call_user_function_ex(EG(function_table), &exception, &backtrace_fname, 
		&trace, 0, NULL, 0, NULL TSRMLS_CC);

	zval_dtor(&backtrace_fname);
	zval_ptr_dtor(&exception);
	if (status != SUCCESS) {
		return;
	}

	/* Write it */
	convert_to_string(trace);
	Z_STRVAL_P(trace) = erealloc( Z_STRVAL_P(trace), Z_STRLEN_P(trace)+sizeof(PHP_EOL) );
	memcpy(Z_STRVAL_P(trace) + Z_STRLEN_P(trace), PHP_EOL, sizeof(PHP_EOL));
	Z_STRLEN_P(trace) += sizeof(PHP_EOL) - 1; /* minus one for null */
	smart_str_appendl(s, Z_STRVAL_P(trace), Z_STRLEN_P(trace));

	zval_ptr_dtor(&trace);
}

/**
 * Write the current URL to a stream
 */
static void wmerrors_write_request_info(smart_str * s TSRMLS_DC) {
	HashTable * server_ht;
	zval **info;
	char *hostname;

	server_ht = Z_ARRVAL_P(PG(http_globals)[TRACK_VARS_SERVER]);

	/* Server */
	hostname = php_get_uname('n');
	smart_str_appends(s, "Server: ");
	smart_str_appends(s, hostname);
	smart_str_appends(s, PHP_EOL);
	efree(hostname);

	/* Method */
	if (SG(request_info).request_method) {
		smart_str_appends(s, "Method: ");
		smart_str_appends(s, SG(request_info).request_method);
		smart_str_appends(s, PHP_EOL);
	}

	/* URL */
	smart_str_appends(s, "URL: ");
	if (zend_hash_find(server_ht, "HTTPS", sizeof("HTTPS"), (void**)(&info)) == SUCCESS) {
		smart_str_appends(s, "https://");
	} else {
		smart_str_appends(s, "http://");
	}
	if (zend_hash_find(server_ht, "HTTP_HOST", sizeof("HTTP_HOST"), (void**)(&info)) == SUCCESS) {
		smart_str_appendl(s, Z_STRVAL_PP(info), Z_STRLEN_PP(info));
	} else {
		smart_str_appends(s, "[unknown-host]");
	}
	if (SG(request_info).request_uri) {
		smart_str_appends(s, SG(request_info).request_uri);
	}
	if (SG(request_info).query_string) {
		smart_str_appendc(s, '?');
		smart_str_appends(s, SG(request_info).query_string);
	}
	smart_str_appends(s, PHP_EOL);

	/* Cookie */
	if (SG(request_info).cookie_data) {
		smart_str_appends(s, "Cookie: ");
		smart_str_appends(s, SG(request_info).cookie_data);
		smart_str_appends(s, PHP_EOL);
	}
}

/**
 * Consistent wrapper for php_escape_html_entities
 * oldlen/newlen were converted from int to size_t
 * October 2010 91727cb844ecfe55f6dcd2f13ffeec3962aabbac 
 */
static char *wmerrors_escape_html_entities(const char *old, size_t oldlen, size_t *newlen TSRMLS_DC)
{
	char * ret;
#if PHP_VERSION_ID < 50399
	const char message[] = "wmerrors: error document larger than 2GB\n";
	int newlen_int;
	if (oldlen > INT_MAX) {
		write(STDERR_FILENO, message, sizeof(message) - 1);
		abort();
	}

	ret = php_escape_html_entities((unsigned char*)old, (int)oldlen, &newlen_int, 0, ENT_COMPAT, NULL TSRMLS_CC);
	if (newlen_int < 0) {
		write(STDERR_FILENO, message, sizeof(message) - 1);
		abort();
	}
	*newlen = (size_t)newlen_int;
#else
	ret = php_escape_html_entities((unsigned char*)old, oldlen, newlen, 0, ENT_COMPAT, NULL TSRMLS_CC);
#endif
	return ret;
}

static void wmerrors_show_message(int type, const char *error_filename, const uint error_lineno, const char *format, va_list args TSRMLS_DC)
{
	php_stream *stream;
	char *message, *p;
	int message_len;
	long maxlen = PHP_STREAM_COPY_ALL;
	char * tmp1, *tmp2;
	size_t tmp1_len, tmp2_len;
	smart_str expanded = { NULL };
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
				tmp1 = wmerrors_escape_html_entities(error_filename,
						strlen(error_filename), &tmp1_len TSRMLS_CC);
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
				tmp2 = wmerrors_escape_html_entities(tmp1, tmp1_len, &tmp2_len TSRMLS_CC);
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

		if (PG(connection_status) & PHP_CONNECTION_TIMEOUT) {
			/* Probably PHP will crash soon, better flush the output first */
			sapi_flush(TSRMLS_C);
		}
	}

	
	/* Clean up */
	smart_str_free(&expanded);
	efree(message);
	va_end(my_args);
}

static const char* wmerrors_error_type_to_string(int type) {
	/** Copied from php_error_cb() */
	switch (type) {
		case E_ERROR:
		case E_CORE_ERROR:
		case E_COMPILE_ERROR:
		case E_USER_ERROR:
			return "Fatal error";
		case E_RECOVERABLE_ERROR:
			return "Catchable fatal error";
		case E_WARNING:
		case E_CORE_WARNING:
		case E_COMPILE_WARNING:
		case E_USER_WARNING:
			return "Warning";
			break;
		case E_PARSE:
			return "Parse error";
		case E_NOTICE:
		case E_USER_NOTICE:
			return "Notice";
		case E_STRICT:
			return "Strict Standards";
#ifdef E_DEPRECATED
		case E_DEPRECATED:
		case E_USER_DEPRECATED:
			return "Deprecated";
#endif
		default:
			return "Unknown error";
	}
}

/**
 * Occasionally, PHP will time out during a malloc() call, generating SIGALRM. 
 * A mutex will be held, and then the process will deadlock forever on the 
 * next malloc() call. This timeout handler is designed to handle this 
 * situation safely.
 *
 * We could try to avoid using malloc(), but then the process would deadlock 
 * when it returns control to Apache.
 */
static void wmerrors_alarm_handler(int signo) {
	const char message[] = "wmerrors: timed out during fatal error handler, aborting\n";
	write(STDERR_FILENO, message, sizeof(message) - 1);
	abort();
}

/**
 * The timer has to be created in advance, since timer_create() calls malloc().
 */
static void wmerrors_create_timer(TSRMLS_D) {
#ifdef WMERRORS_USE_TIMER
	struct sigaction sa;
	struct sigevent evp;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = wmerrors_alarm_handler;
	sigaction(SIGRTMIN+3, &sa, &WMERRORS_G(old_rt_action));

	evp.sigev_notify = SIGEV_SIGNAL;
	evp.sigev_signo = SIGRTMIN+3;
	if (timer_create(CLOCK_REALTIME, &evp, &WMERRORS_G(timer)) == -1) {
		perror("timer_create");
		abort();
	}
	WMERRORS_G(timer_created) = 1;
#endif
}

static void wmerrors_start_timer(TSRMLS_D) {
#ifdef WMERRORS_USE_TIMER
	if (!WMERRORS_G(timer_created)) {
		return;
	}
	struct itimerspec its;
	its.it_value.tv_sec = WMERRORS_G(timeout);
	its.it_value.tv_nsec = 0;
	its.it_interval.tv_sec = its.it_interval.tv_nsec = 0;
	timer_settime(WMERRORS_G(timer), 0, &its, NULL);
#endif
}

static void wmerrors_destroy_timer(TSRMLS_D) {
#ifdef WMERRORS_USE_TIMER
	if (WMERRORS_G(timer_created)) {
		timer_delete(WMERRORS_G(timer));
		WMERRORS_G(timer_created) = 0;
		sigaction(SIGRTMIN+3, &WMERRORS_G(old_rt_action), NULL);
	}
#endif
}

PHP_FUNCTION(wmerrors_malloc_test) {
	for (;;) {
		free(malloc(100));
	}
}
