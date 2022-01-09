
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#include "php.h"
#include "php_ini.h"
#include "php_main.h"
#include "php_wmerrors.h"
#include "ext/standard/php_standard.h"
#include "SAPI.h" /* for sapi_module */
#include "ext/date/php_date.h" /* for php_format_date */
#include "ext/standard/php_smart_string.h" /* for smart_string */
#include "Zend/zend_builtin_functions.h" /* for zend_fetch_debug_backtrace */
#include "Zend/zend_exceptions.h" /* for zend_ce_exception */

#if PHP_VERSION_ID >= 80100
#define wmerrors_error_filename zend_string
#else
#define wmerrors_error_filename const char
#endif

#if PHP_VERSION_ID >= 80000
#define wmerrors_message zend_string *message
#define wmerrors_message_args message
#else
#define wmerrors_message const char *format, va_list args
#define wmerrors_message_args format, args
#endif

static int wmerrors_post_deactivate();
static void wmerrors_cb(int type, wmerrors_error_filename *error_filename, const uint32_t error_lineno, wmerrors_message);
static void wmerrors_show_message(int type, wmerrors_error_filename *error_filename, const uint32_t error_lineno, wmerrors_message);
static void wmerrors_get_concise_backtrace(smart_string *s);
static void wmerrors_write_full_backtrace(smart_string *s);
static void wmerrors_write_request_info(smart_string *s);
static void wmerrors_execute_file(int type, wmerrors_error_filename *error_filename, const uint32_t error_lineno, wmerrors_message);

ZEND_DECLARE_MODULE_GLOBALS(wmerrors)

PHP_FUNCTION(wmerrors_malloc_test);

ZEND_BEGIN_ARG_INFO(wmerrors_malloc_test_arginfo, 0)
ZEND_END_ARG_INFO()

zend_function_entry wmerrors_functions[] = {
	PHP_FE(wmerrors_malloc_test, wmerrors_malloc_test_arginfo)
	{NULL, NULL, NULL}
};


zend_module_entry wmerrors_module_entry = {
	STANDARD_MODULE_HEADER,
	"wmerrors",
	wmerrors_functions,
	PHP_MINIT(wmerrors),
	PHP_MSHUTDOWN(wmerrors),
	PHP_RINIT(wmerrors),
	PHP_RSHUTDOWN(wmerrors),
	PHP_MINFO(wmerrors),
	"1.2.0",
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
	STD_PHP_INI_ENTRY("wmerrors.error_script_file", "", PHP_INI_ALL, OnUpdateString, error_script_file, zend_wmerrors_globals, wmerrors_globals)
	STD_PHP_INI_ENTRY("wmerrors.log_file", "", PHP_INI_ALL, OnUpdateString, log_file, zend_wmerrors_globals, wmerrors_globals)
	STD_PHP_INI_BOOLEAN("wmerrors.log_backtrace", "0", PHP_INI_ALL, OnUpdateBool, log_backtrace, zend_wmerrors_globals, wmerrors_globals)
	STD_PHP_INI_ENTRY("wmerrors.log_line_prefix", "", PHP_INI_ALL, OnUpdateString, log_line_prefix, zend_wmerrors_globals, wmerrors_globals)
	STD_PHP_INI_BOOLEAN("wmerrors.ignore_logging_errors", "0", PHP_INI_ALL, OnUpdateBool, ignore_logging_errors, zend_wmerrors_globals, wmerrors_globals)
	STD_PHP_INI_BOOLEAN("wmerrors.backtrace_in_php_error_message", "0", PHP_INI_ALL, OnUpdateBool, backtrace_in_php_error_message, zend_wmerrors_globals, wmerrors_globals)
PHP_INI_END()

void (*old_error_cb)(int type, wmerrors_error_filename *error_filename, const uint32_t error_lineno, wmerrors_message);

static void php_wmerrors_init_globals(zend_wmerrors_globals *wmerrors_globals)
{
	memset(wmerrors_globals, 0, sizeof(zend_wmerrors_globals));
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

int wmerrors_post_deactivate()
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

static const char* wmerrors_error_type_to_string(int type);
static void wmerrors_log_error(int type, wmerrors_error_filename *error_filename, const uint32_t error_lineno, wmerrors_message);

static void wmerrors_cb(int type, wmerrors_error_filename *error_filename, const uint32_t error_lineno, wmerrors_message)
{
	smart_string new_filename = { NULL };

	/* Do not call the custom error handling if:
	 * it's not enabled,
	 * OR the error is not one of E_{,CORE_,COMPILE_,USER_,RECOVERABLE_}ERROR,
	 * OR the error is an E_RECOVERABLE_ERROR and is being thrown as an exception,
	 * OR it's triggering itself (recursion guard)
	 */
	if ( !WMERRORS_G(enabled)
			|| (type == E_RECOVERABLE_ERROR && EG(error_handling) == EH_THROW && !EG(exception))
			|| (type != E_ERROR && type != E_CORE_ERROR && type != E_COMPILE_ERROR
			      && type != E_USER_ERROR && type != E_RECOVERABLE_ERROR)
			|| WMERRORS_G(recursion_guard))
	{
		/* recursion_guard != 1 means this is an error in writing to the log file.
		 * Ignore it if configured to do so.
		 */
		if (WMERRORS_G(recursion_guard) == 1 || !WMERRORS_G(ignore_logging_errors))
			old_error_cb(type, error_filename, error_lineno, wmerrors_message_args);
		return;
	}
	WMERRORS_G(recursion_guard) = 1;
	/* No more OOM errors for now thanks */
	zend_set_memory_limit((size_t)-1);

	/* Do not show the html error to console */
	if ( WMERRORS_G(enabled) && strncmp(sapi_module.name, "cli", 3) ) {
		/* Show the message */
		if (WMERRORS_G(error_script_file) && WMERRORS_G(error_script_file)[0] != '\0') {
			wmerrors_execute_file(type, error_filename, error_lineno, wmerrors_message_args);
		} else if (WMERRORS_G(message_file) && WMERRORS_G(message_file)[0] != '\0') {
			wmerrors_show_message(type, error_filename, error_lineno, wmerrors_message_args);
		}
	}

	if ( WMERRORS_G(enabled) ) {
		/* Log the error */
		wmerrors_log_error(type, error_filename, error_lineno, wmerrors_message_args);
	}

	/* Put a concise backtrace in the normal output */
	if (WMERRORS_G(backtrace_in_php_error_message)) {
		wmerrors_get_concise_backtrace(&new_filename);
	}

	smart_string_appendl(
		&new_filename,
#if PHP_VERSION_ID >= 80100
		ZSTR_VAL(error_filename),
		ZSTR_LEN(error_filename)
#else
		error_filename,
		strlen(error_filename)
#endif
	);
	smart_string_0(&new_filename);

	WMERRORS_G(recursion_guard) = 0;
	zend_set_memory_limit(PG(memory_limit));

	/* Pass through */
	old_error_cb(
		type,
#if PHP_VERSION_ID >= 80100
		zend_string_init(new_filename.c, new_filename.len, 0),
#else
		new_filename.c,
#endif
		error_lineno,
		wmerrors_message_args
	);
	/* Note: old_error_cb() may not return, in which case there will be no
	 * explicit free of new_filename */
	smart_string_free(&new_filename);
}

/* Obtain a concisely formatted backtrace */
static void wmerrors_get_concise_backtrace(smart_string *s) {
	zval trace = {}, *entry, *file, *line;
	HashPosition pos;
	zend_string *basename;

	zend_fetch_debug_backtrace(&trace, 0, 0, 1000);

	if (Z_TYPE(trace) != IS_ARRAY) {
		/* Not supposed to happen */
		zval_dtor(&trace);
		return;
	}

	zend_hash_internal_pointer_reset_ex(Z_ARRVAL(trace), &pos);
	ZEND_HASH_FOREACH_VAL(Z_ARRVAL(trace), entry) {
		if (!entry || Z_TYPE_P(entry) != IS_ARRAY) {
			/* Not supposed to happen */
			smart_string_appendl(s, "?!? ", sizeof("?!? "));
			continue;
		}

		file = zend_hash_str_find(Z_ARRVAL_P(entry), ZEND_STRL("file"));
		line = zend_hash_str_find(Z_ARRVAL_P(entry), ZEND_STRL("line"));

		if (!file || Z_TYPE_P(file) != IS_STRING || !line || Z_TYPE_P(line) != IS_LONG) {
			/* Not supposed to happen */
			smart_string_appendl(s, "?!?!? ", sizeof("?!?!? "));
			continue;
		}
		basename = php_basename(Z_STRVAL_P(file), Z_STRLEN_P(file), NULL, 0);
		smart_string_appendl(s, ZSTR_VAL(basename), ZSTR_LEN(basename));
		smart_string_appendc(s, ':');
		smart_string_append_long(s, Z_LVAL_P(line));
		smart_string_appendc(s, ' ');

		zend_string_free(basename);
	} ZEND_HASH_FOREACH_END();
	zval_dtor(&trace);
}

static php_stream * wmerrors_open_log_file(const char* stream_name) {
	php_stream * stream;
	int err; zend_string *errstr = NULL;
	struct timeval tv;
	int flags = 0;

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

	if (errstr) {
		zend_string_release(errstr);
	}

	/* Set the chunk size to something fairly large, to avoid fragmentation */
	if (stream) {
		php_stream_set_option(stream, PHP_STREAM_OPTION_SET_CHUNK_SIZE, 65507, NULL);
	}
	return stream;
}

static void wmerrors_log_error(int type, wmerrors_error_filename *error_filename, const uint32_t error_lineno, wmerrors_message) {
	char *first_line;
	int first_line_len;
	char error_time_str[256];
	time_t simpleTime;
	struct tm brokenTime;
	php_stream *logfile_stream;
	smart_string our_message = {NULL};
	smart_string prefixed_message = {NULL};

	if ( !WMERRORS_G(log_file) || *WMERRORS_G(log_file) == '\0') {
		/* No log file configured */
		return;
	}

#if PHP_VERSION_ID < 80000
	char *input_message;
	int input_message_len;
	va_list my_args;

	/* Don't destroy the caller's va_list */
	va_copy(my_args, args);
	/* Write the input message */
	input_message_len = vspprintf(&input_message, 0, format, my_args);
	va_end(my_args);
#endif

	/* Try opening the logging file */
	/* Set recursion_guard==2 whenever we're doing something to the log file */
	WMERRORS_G(recursion_guard) = 2;
	logfile_stream = wmerrors_open_log_file(WMERRORS_G(log_file));
	WMERRORS_G(recursion_guard) = 1;
	if ( !logfile_stream ) {
		return;
	}

	/* Get a date string */
	simpleTime = time(NULL);
	localtime_r(&simpleTime, &brokenTime);
	strftime(error_time_str, sizeof(error_time_str), "%Y-%m-%d %H:%M:%S", &brokenTime);

	/* Make the initial log line */
	first_line_len = spprintf(&first_line, 0, "[%s] %s: %.*s at %s on line %u%s",
			error_time_str, wmerrors_error_type_to_string(type),
#if PHP_VERSION_ID >= 80000
			ZSTR_LEN(message), ZSTR_VAL(message),
#else
			input_message_len, input_message,
#endif
#if PHP_VERSION_ID >= 80100
			ZSTR_VAL(error_filename),
#else
			error_filename,
#endif
			error_lineno, PHP_EOL);
	smart_string_appendl(&our_message, first_line, first_line_len);
#if PHP_VERSION_ID < 80000
	efree(input_message);
#endif
	efree(first_line);

	/* Write the request info */
	wmerrors_write_request_info(&our_message);

	/* Write a backtrace */
	if ( WMERRORS_G(log_backtrace) ) {
		smart_string_appends(&our_message, "Backtrace:");
		smart_string_appends(&our_message, PHP_EOL);
		wmerrors_write_full_backtrace(&our_message);
	}

	/* Add the log line prefix if requested */
	if (our_message.c && WMERRORS_G(log_line_prefix) && WMERRORS_G(log_line_prefix)[0]) {
		char * line_start = our_message.c;
		char * message_end = our_message.c + our_message.len;
		char * line_end;
		while (line_start < message_end) {
			smart_string_appends(&prefixed_message, WMERRORS_G(log_line_prefix));
			line_end = memchr(line_start, '\n', message_end - line_start);
			if (!line_end) {
				line_end = message_end - 1;
			}
			smart_string_appendl(&prefixed_message, line_start, line_end - line_start + 1);
			line_start = line_end + 1;
		}
		smart_string_free(&our_message);
	} else {
		prefixed_message = our_message;
	}

	WMERRORS_G(recursion_guard) = 2;
	if (prefixed_message.c) {
		php_stream_write(logfile_stream, prefixed_message.c, prefixed_message.len);
	}
	php_stream_close(logfile_stream);
	WMERRORS_G(recursion_guard) = 1;
	smart_string_free(&prefixed_message);
}


/**
 * Write a backtrace to a string
 */
static void wmerrors_write_full_backtrace(smart_string * s) {
	zval trace;
	zval backtrace_fname;
	int status;
	zval exception;

	/* Create an Exception object */
	object_init_ex(&exception, zend_ce_exception);

	/* Call Exception::getTraceAsString() */
	ZVAL_STRING(&backtrace_fname, "getTraceAsString");
	status = call_user_function(NULL, &exception, &backtrace_fname,
		&trace, 0, NULL);

	zval_dtor(&backtrace_fname);
	zval_ptr_dtor(&exception);
	if (status != SUCCESS) {
		return;
	}

	/* Write it */
	convert_to_string(&trace);
	smart_string_appendl(s, Z_STRVAL(trace), Z_STRLEN(trace));
	smart_string_appends(s, PHP_EOL);

	zval_dtor(&trace);
}

/**
 * Write the current URL to a string
 */
static void wmerrors_write_request_info(smart_string * s) {
	HashTable * server_ht;
	zend_string *hostname;

	if (zend_is_auto_global_str("_SERVER", sizeof("_SERVER") - 1)) {
		server_ht = Z_ARRVAL(PG(http_globals)[TRACK_VARS_SERVER]);
	} else {
		server_ht = NULL;
	}

	/* Server */
	hostname = php_get_uname('n');
	smart_string_appends(s, "Server: ");
	smart_string_appends(s, ZSTR_VAL(hostname));
	smart_string_appends(s, PHP_EOL);
	zend_string_release(hostname);

	/* Method */
	if (SG(request_info).request_method) {
		smart_string_appends(s, "Method: ");
		smart_string_appends(s, SG(request_info).request_method);
		smart_string_appends(s, PHP_EOL);
	}

	/* URL */
	smart_string_appends(s, "URL: ");

	zval *info = server_ht ? zend_hash_str_find(server_ht, ZEND_STRL("HTTPS")) : NULL;
	if (info) {
		smart_string_appends(s, "https://");
	} else {
		smart_string_appends(s, "http://");
	}

	info = server_ht ? zend_hash_str_find(server_ht, ZEND_STRL("HTTP_HOST")) : NULL;
	if (info) {
		smart_string_appendl(s, Z_STRVAL_P(info), Z_STRLEN_P(info));
	} else {
		smart_string_appends(s, "[unknown-host]");
	}

	if (SG(request_info).request_uri) {
		smart_string_appends(s, SG(request_info).request_uri);
	}
	if (SG(request_info).query_string && SG(request_info).query_string[0]) {
		smart_string_appendc(s, '?');
		smart_string_appends(s, SG(request_info).query_string);
	}
	smart_string_appends(s, PHP_EOL);

	/* Cookie */
	if (SG(request_info).cookie_data) {
		smart_string_appends(s, "Cookie: ");
		smart_string_appends(s, SG(request_info).cookie_data);
		smart_string_appends(s, PHP_EOL);
	}
}

static zend_string *wmerrors_escape_html_entities(const char *old, size_t oldlen)
{
	return php_escape_html_entities((unsigned char*)old, oldlen, 0, ENT_COMPAT, NULL);
}

static void wmerrors_show_message(int type, wmerrors_error_filename *error_filename, const uint32_t error_lineno, wmerrors_message)
{
	php_stream *stream;
	zend_string *our_message;
	long maxlen = PHP_STREAM_COPY_ALL;
	smart_string expanded = { NULL };

	/* Open the message file */
	stream = php_stream_open_wrapper(WMERRORS_G(message_file), "rb",
			REPORT_ERRORS, NULL);
	if (!stream) {
		return;
	}

#if PHP_VERSION_ID < 80000
	va_list my_args;
	/* Don't destroy the caller's va_list */
	va_copy(my_args, args);
#endif

	/* Read the contents */
	our_message = php_stream_copy_to_mem(stream, maxlen, 0);
	php_stream_close(stream);

	/* Replace some tokens */
	for (char *p = ZSTR_VAL(our_message); p < ZSTR_VAL(our_message) + ZSTR_LEN(our_message); p++) {
		if (*p == '$') {
			if (!strncmp(p, "$file", sizeof("$file")-1)) {
				zend_string *str = wmerrors_escape_html_entities(
#if PHP_VERSION_ID >= 80100
					ZSTR_VAL(error_filename), ZSTR_LEN(error_filename)
#else
					error_filename, strlen(error_filename)
#endif
				);
				smart_string_appendl(&expanded, ZSTR_VAL(str), ZSTR_LEN(str));
				zend_string_release(str);
				p += sizeof("file") - 1;
			} else if (!strncmp(p, "$line", sizeof("$line")-1)) {
				smart_string_append_unsigned(&expanded, (zend_ulong)error_lineno);
				p += sizeof("line") - 1;
			} else if (!strncmp(p, "$message", sizeof("$message")-1)) {
#if PHP_VERSION_ID >= 80000
				zend_string *str = wmerrors_escape_html_entities(ZSTR_VAL(message), ZSTR_LEN(message));
				smart_string_appendl(&expanded, ZSTR_VAL(str), ZSTR_LEN(str));
#else
				/* Don't destroy args */
				char *buf;
				size_t len = vspprintf(&buf, 0, format, my_args);
				zend_string *str = wmerrors_escape_html_entities(buf, len);
				smart_string_appendl(&expanded, ZSTR_VAL(str), ZSTR_LEN(str));
				efree(buf);
#endif
				zend_string_release(str);
				p += sizeof("message") - 1;
			} else {
				smart_string_appendc(&expanded, '$');
			}
		} else {
			smart_string_appendc(&expanded, *p);
		}
	}

	/* Set headers */
	if (!SG(headers_sent)) {
		sapi_header_line ctr = {0};

		ctr.line = "HTTP/1.0 500 Internal Server Error";
		ctr.line_len = strlen(ctr.line);
		sapi_header_op(SAPI_HEADER_REPLACE, &ctr);
	}

	/* Write the message out */
	if (expanded.c) {
		php_write(expanded.c, expanded.len);
	}


	/* Clean up */
	smart_string_free(&expanded);
#if PHP_VERSION_ID < 80000
	va_end(my_args);
#endif
	zend_string_release(our_message);
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
			return "Recoverable fatal error";
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
		case E_DEPRECATED:
		case E_USER_DEPRECATED:
			return "Deprecated";
		default:
			return "Unknown error";
	}
}

PHP_FUNCTION(wmerrors_malloc_test) {
	for (;;) {
		free(malloc(100));
	}
}

static void wmerrors_execute_file(int type, wmerrors_error_filename *error_filename, const uint32_t error_lineno, wmerrors_message) {
	/* Copy the error message into PG(...), as in php_error_cb(), so that the
	 * invoked script can get the error details from error_get_last(). */
#if PHP_VERSION_ID < 80000
	char *buffer;
	size_t buffer_len;
	va_list my_args;

	/* Don't destroy the caller's va_list */
	va_copy(my_args, args);
	buffer_len = vspprintf(&buffer, PG(log_errors_max_len), format, my_args);
	va_end(my_args);
#endif

	if (PG(last_error_message)) {
		free(PG(last_error_message));
		PG(last_error_message) = NULL;
	}
	if (PG(last_error_file)) {
		free(PG(last_error_file));
		PG(last_error_file) = NULL;
	}
	if (!error_filename) {
#if PHP_VERSION_ID >= 80100
		error_filename = ZSTR_KNOWN(ZEND_STR_UNKNOWN_CAPITALIZED);
#else
		error_filename = "Unknown";
#endif
	}
	PG(last_error_type) = type;
#if PHP_VERSION_ID >= 80000
	PG(last_error_message) = zend_string_copy(message);
#else
	PG(last_error_message) = strndup(buffer, buffer_len);
#endif
#if PHP_VERSION_ID >= 80100
	PG(last_error_file) = zend_string_copy(error_filename);
#else
	PG(last_error_file) = strdup(error_filename);
#endif
	PG(last_error_lineno) = error_lineno;

#if PHP_VERSION_ID < 80000
	efree(buffer);
#endif

	/* Open the file and execute it as PHP.
	 *
	 * This part follows spl_autoload(), which is a rare example of an extension
	 * invoking a PHP file.
	 *
	 * A comment in the PHP source states that it is unsafe to run userspace code
	 * while handling an error. There are fewer reasons for that to be true now
	 * than when that comment was written. The main remaining concern is that
	 * the error handler may be invoked from within any emalloc() call. The global
	 * state may be invalid at this time, since extensions generally do not expect
	 * that emalloc() may execute userspace code.
	 *
	 * The PHP core will call userspace code on OOM only after zend_bailout() is
	 * called, which resets the stack. That would probably be safer, but would
	 * remove the ability for the called code to inspect the backtrace.
	 */
	int ret;
	zval result;
	zend_file_handle file_handle;
	zend_op_array *new_op_array;

#if PHP_VERSION_ID >= 80100
	zend_stream_init_filename(&file_handle, WMERRORS_G(error_script_file));
	ret = php_stream_open_for_zend_ex(&file_handle, STREAM_OPEN_FOR_INCLUDE);
#else
	ret = php_stream_open_for_zend_ex(WMERRORS_G(error_script_file), &file_handle, STREAM_OPEN_FOR_INCLUDE);
#endif
	if (ret == SUCCESS) {
		new_op_array = zend_compile_file(&file_handle, ZEND_INCLUDE);
		if (new_op_array) {
			ZVAL_UNDEF(&result);
			zend_execute(new_op_array, &result);
			zend_destroy_file_handle(&file_handle);
			destroy_op_array(new_op_array);
			efree(new_op_array);
			zval_ptr_dtor(&result);
		}
	}
}
