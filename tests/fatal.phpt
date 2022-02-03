--TEST--
Fatal error logged
--SKIPIF--
<?php if (!extension_loaded("wmerrors")) print "skip"; ?>
--INI--
wmerrors.enabled=On
wmerrors.backtrace_in_php_error_message=On
wmerrors.log_file="php://stdout";
wmerrors.log_backtrace=On
display_errors=Off
--FILE--
<?php
function main() {
    new UndefinedClass();
}

main();
--EXPECTF--
[%d-%d-%d %d:%d:%d] Fatal error: Uncaught Error: Class %cUndefinedClass%c not found in %r(.*?)%r/tests/fatal.php:3
Stack trace:
#0 %r(.*?)%r/tests/fatal.php(6): main()
#1 {main}
  thrown at %r(.*?)%r/tests/fatal.php on line 3
Server: %r(.*?)%r
URL: http://[unknown-host]
Backtrace:
#0 {main}
