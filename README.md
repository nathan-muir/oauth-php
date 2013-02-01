oauth-php
=========

A re-implementation for PHP 5.3 based on [Andy Smith's](http://term.ie/) [basic php library](http://oauth.googlecode.com/svn/code/php/) for OAuth.

 * improved exception handling by adding BadRequestException, and UnauthorisedException. Allows the server to respond readily with Http 400/ 401 status codes.
 * Added provisions to the consumer class for SignatureMethods, UserIDs and Host IP Checks.
 * Added provisions to the token for selecting a UserID