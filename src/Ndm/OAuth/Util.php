<?php
namespace Ndm\OAuth;
/**
 *
 */
class Util
{
	/**
	 * @param $input
	 * @return array|mixed|string
	 */
	public static function urlEncodeRfc3986($input)
	{
		if (is_array($input)) {
			return array_map(array('\\Ndm\\OAuth\\Util', 'urlEncodeRfc3986'), $input);
		} else if (is_scalar($input)) {
			return str_replace(
				'+',
				' ',
				str_replace('%7E', '~', rawurlencode($input))
			);
		} else {
			return '';
		}
	}

	/**
	 * This decode function isn't taking into consideration the above
	 * modifications to the encoding process. However, this method doesn't
	 * seem to be used anywhere so leaving it as is.
	 * @param $string
	 * @return string
	 */
	public static function urlDecodeRfc3986($string)
	{
		return urldecode($string);
	}

	/**
	 * Utility function for turning the Authorization: header into
	 * parameters, has to do some unescaping
	 * Can filter out any non-oauth parameters if needed (default behaviour)
	 * @param $header
	 * @param bool $onlyAllowOauthParameters
	 * @return array
	 */
	public static function splitHeader($header, $onlyAllowOauthParameters = true)
	{
		$pattern = '/(([-_a-z]*)=("([^"]*)"|([^,]*)),?)/';
		$offset = 0;
		$params = array();
		while (preg_match($pattern, $header, $matches, PREG_OFFSET_CAPTURE, $offset) > 0) {
			$match = $matches[0];
			$headerName = $matches[2][0];
			$headerContent = (isset($matches[5])) ? $matches[5][0] : $matches[4][0];
			if (preg_match('/^oauth_/', $headerName) || !$onlyAllowOauthParameters) {
				$params[$headerName] = self::urlDecodeRfc3986($headerContent);
			}
			$offset = $match[1] + strlen($match[0]);
		}

		if (isset($params['realm'])) {
			unset($params['realm']);
		}

		return $params;
	}

	/**
	 * helper to try to sort out headers for people who aren't running apache
	 * @return array
	 */
	public static function getHeaders()
	{
		if (function_exists('apache_request_headers')) {
			// we need this to get the actual Authorization: header
			// because apache tends to tell us it doesn't exist
			$headers = apache_request_headers();

			// sanitize the output of apache_request_headers because
			// we always want the keys to be Cased-Like-This and arh()
			// returns the headers in the same case as they are in the
			// request
			$out = array();
			foreach ($headers AS $key => $value) {
				$key = str_replace(
					" ",
					"-",
					ucwords(strtolower(str_replace("-", " ", $key)))
				);
				$out[$key] = $value;
			}
		} else {
			// otherwise we don't have apache and are just going to have to hope
			// that $_SERVER actually contains what we need
			$out = array();
			foreach ($_SERVER as $key => $value) {
				if ($key == 'CONTENT_TYPE'){
					$key = str_replace(
						" ",
						"-",
						ucwords(strtolower(str_replace("_", " ", $key)))
					);
					$out[$key] = $value;
				} else if (substr($key, 0, 5) == "HTTP_") {
					// this is chaos, basically it is just there to capitalize the first
					// letter of every word that is not an initial HTTP and strip HTTP
					// code from przemek
					$key = str_replace(
						" ",
						"-",
						ucwords(strtolower(str_replace("_", " ", substr($key, 5))))
					);
					$out[$key] = $value;
				}
			}
		}
		return $out;
	}

	/**
	 * This function takes a input like a=b&a=c&d=e and returns the parsed
	 * parameters like this
	 * array('a' => array('b','c'), 'd' => 'e')
	 * @param $input
	 * @return array
	 */
	public static function parseParameters($input)
	{
		if (!isset($input) || !$input) return array();

		$pairs = explode('&', $input);

		$parsedParameters = array();
		foreach ($pairs as $pair) {
			$split = explode('=', $pair, 2);
			$parameter = self::urlDecodeRfc3986($split[0]);
			$value = isset($split[1]) ? self::urlDecodeRfc3986($split[1]) : '';

			if (isset($parsedParameters[$parameter])) {
				// We have already recieved parameter(s) with this name, so add to the list
				// of parameters with this name

				if (is_scalar($parsedParameters[$parameter])) {
					// This is the first duplicate, so transform scalar (string) into an array
					// so we can add the duplicates
					$parsedParameters[$parameter] = array($parsedParameters[$parameter]);
				}

				$parsedParameters[$parameter][] = $value;
			} else {
				$parsedParameters[$parameter] = $value;
			}
		}
		return $parsedParameters;
	}

	/**
	 * @param $params
	 * @return string
	 */
	public static function buildHttpQuery($params)
	{
		if (!$params) return '';

		// Urlencode both keys and values
		$keys = self::urlEncodeRfc3986(array_keys($params));
		$values = self::urlEncodeRfc3986(array_values($params));
		$params = array_combine($keys, $values);

		// Parameters are sorted by name, using lexicographical byte value ordering.
		// Ref: Spec: 9.1.1 (1)
		uksort($params, 'strcmp');

		$pairs = array();
		foreach ($params as $parameter => $value) {
			if (is_array($value)) {
				// If two or more parameters share the same name, they are sorted by their value
				// Ref: Spec: 9.1.1 (1)
				natsort($value);
				foreach ($value as $duplicateValue) {
					$pairs[] = $parameter . '=' . $duplicateValue;
				}
			} else {
				$pairs[] = $parameter . '=' . $value;
			}
		}
		// For each parameter, the name is separated from the corresponding value by an '=' character (ASCII code 61)
		// Each name-value pair is separated by an '&' character (ASCII code 38)
		return implode('&', $pairs);
	}


	/**
	 * @param mixed $data
	 *
	 * @return string
	 */
	public static function base64UrlEncode($data) {
	  return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
	}


	/**
	 * @param string $data
	 *
	 * @return mixed
	 */
	public static function base64UrlDecode($data) {
	  return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
	}


	/**@#+
	 * @const Token/Key lengths in bytes
	 */
	const TOKEN_LENGTH = 32;

    /**
     *
     */
    const SECRET_LENGTH = 64;

	/**
	 * Creates a token packed with version number and type.
     *
     * Can be expanded apon at a later time.
     *
	 * @param string     $tokenType
	 * @return Token
	 */
	public static function createToken($tokenType){

		// start the token
		$token = '';
		$token .= pack('n', 1); // pack version number as unsigned short
        // pack the token type as an ascii-char
		$token .= pack('C', ord($tokenType == Token::TYPE_ACCESS ? 'a' : 'r'));
		// create length-bits of random data
		$token .= self::getRandomBytes(self::TOKEN_LENGTH);
		// keeps total "entropy" the same but allow for easier transportation
		$token_base64 = self::base64UrlEncode($token);
        // create the secret
		$token_secret_base64 = self::base64UrlEncode(self::getRandomBytes(self::SECRET_LENGTH));
        // return the token
		return new Token($token_base64, $token_secret_base64);
	}


	/**
	 * @param int $length the number of bytes to get
	 * @return string
	 */
	public static function getRandomBytes($length){
		return openssl_random_pseudo_bytes($length);
	}

	/**
	 * Checks if an ip address is in a cidr range
	 *
	 * @param string|null $hostNetwork
	 * @param string|null $ipAddress
	 *
	 * @return bool
	 */
	public static function networkMatch($hostNetwork, $ipAddress){

		// php 5.4 ipv6 address crapness
		$ipAddress = preg_replace('~^::ffff:~','',$ipAddress);
		$ip = ip2long($ipAddress);

		if($ip === false) return false;

		if (strpos($hostNetwork,'/') === false){
			// ip-address comparison
			$host = ip2long($hostNetwork);
			return $host === $ip;
		} else {
			$networkArr = explode('/',$hostNetwork);
			$networkMaskIp = ip2long($networkArr[0]);
			// if mask is 0 then return true
			if (empty($networkArr[1])) return true;

			$networkMaskBits = 32 - $networkArr[1];

			return ($ip >> $networkMaskBits) == ($networkMaskIp >> $networkMaskBits);
		}
	}
}