<?php
namespace Ndm\OAuth;
/**
 *
 */
class Request
{
	/**
	 * @var array
	 */
	private $parameters;
	/**
	 * @var string
	 */
	private $httpMethod;
	/**
	 * @var string
	 */
	private $httpUrl;
	/**
	 * @var array
	 */
	private $excludeParameters = array();

	/**
	 * @var string|null
	 */
	public $remoteAddress;

	// for debug purposes
	/**
	 * @var string
	 */
	public $baseString;
	/**
	 * @var string
	 */
	public static $version = '1.0';
	/**
	 * @var string
	 */
	public static $postInput = 'php://input';


	/**
	 * @param $httpMethod
	 * @param $httpUrl
	 * @param null $parameters
	 */
	function __construct($httpMethod, $httpUrl, $parameters = null)
	{
		@$parameters or $parameters = array();
		$parameters = array_merge(Util::parseParameters(parse_url($httpUrl, PHP_URL_QUERY)), $parameters);
		$this->parameters = $parameters;
		$this->httpMethod = $httpMethod;
		$this->httpUrl = $httpUrl;
	}


	/**
	 * attempt to build up a request from what was passed to the server
	 * @param string|null $httpMethod
	 * @param string|null $httpUrl
	 * @param array|null $parameters
	 * @return Request
	 */
	public static function fromRequest($httpMethod = null, $httpUrl = null, $parameters = null)
	{
		$scheme = (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] != "on")
			? 'http'
			: 'https';
		@$httpUrl or $httpUrl = $scheme .
			'://' . $_SERVER['HTTP_HOST'] .
			':' .
			$_SERVER['SERVER_PORT'] .
			$_SERVER['REQUEST_URI'];
		@$httpMethod or $httpMethod = $_SERVER['REQUEST_METHOD'];

		// We weren't handed any parameters, so let's find the ones relevant to
		// this request.
		// If you run XML-RPC or similar you should use this to provide your own
		// parsed parameter-list
		if (!$parameters) {
			// Find request headers
			$requestHeaders = Util::getHeaders();
			// Parse the query-string to find GET parameters
			$parameters = Util::parseParameters($_SERVER['QUERY_STRING']);

			// It's a POST request of the proper content-type, so parse POST
			// parameters and add those overriding any duplicates from GET
			if ($httpMethod == "POST"
				&& @strstr($requestHeaders["Content-Type"],
					"application/x-www-form-urlencoded")
			) {
				$postData = Util::parseParameters(
					file_get_contents(self::$postInput)
				);
				$parameters = array_merge($parameters, $postData);
			}

			// We have a Authorization-header with OAuth data. Parse the header
			// and add those overriding any duplicates from GET or POST
			if (isset($requestHeaders['Authorization']) && preg_match('/^OAuth\b/',$requestHeaders['Authorization'])) {
				$headerParameters = Util::splitHeader(
					$requestHeaders['Authorization']
				);
				$parameters = array_merge($parameters, $headerParameters);
			}

		}

		$OAuthRequest =  new Request($httpMethod, $httpUrl, $parameters);
		$OAuthRequest->remoteAddress = $_SERVER['REMOTE_ADDR'];
		return $OAuthRequest;
	}

	/**
	 * pretty much a helper function to set up the request
	 * @param Consumer $consumer
	 * @param Token $token
	 * @param string $httpMethod
	 * @param string $httpUrl
	 * @param array|null $parameters
	 * @return Request
	 */
	public static function fromConsumerAndToken(Consumer $consumer, Token $token = null, $httpMethod = 'GET', $httpUrl = '', $parameters = null)
	{
		@$parameters or $parameters = array();
		$defaults = array("oauth_version" => self::$version,
			"oauth_nonce" => self::generateNonce(),
			"oauth_timestamp" => self::generateTimestamp(),
			"oauth_consumer_key" => $consumer->key);
		if ($token)
			$defaults['oauth_token'] = $token->key;

		$parameters = array_merge($defaults, $parameters);

		return new Request($httpMethod, $httpUrl, $parameters);
	}

	/**
	 * @param string $name
	 * @param string $value
	 * @param bool $allowDuplicates
	 */
	public function setParameter($name, $value, $allowDuplicates = true)
	{
		if ($allowDuplicates && isset($this->parameters[$name])) {
			// We have already added parameter(s) with this name, so add to the list
			if (is_scalar($this->parameters[$name])) {
				// This is the first duplicate, so transform scalar (string)
				// into an array so we can add the duplicates
				$this->parameters[$name] = array($this->parameters[$name]);
			}

			$this->parameters[$name][] = $value;
		} else {
			$this->parameters[$name] = $value;
		}
	}

	/**
	 * @param string $name
	 * @return mixed
	 */
	public function getParameter($name)
	{
		return isset($this->parameters[$name]) ? $this->parameters[$name] : null;
	}

	/**
	 * @return array
	 */
	public function getParameters()
	{
		return $this->parameters;
	}

	/**
	 * @param string $name
	 */
	public function unsetParameter($name)
	{
		unset($this->parameters[$name]);
	}

	/**
	 * The request parameters, sorted and concatenated into a normalized string.
	 * @return string
	 */
	public function getSignableParameters()
	{
		// Grab all parameters
		$params = $this->parameters;

		// Remove oauth_signature if present
		// Ref: Spec: 9.1.1 ("The oauth_signature parameter MUST be excluded.")
		if (isset($params['oauth_signature'])) {
			unset($params['oauth_signature']);
		}
		// remove additional params, like routes from re-writes etc
		foreach($this->excludeParameters as $paramName){
			if (isset($params[$paramName])) unset($params[$paramName]);
		}
		return Util::buildHttpQuery($params);
	}


	/**
	 * @param $param
	 */
	public function excludeParameter($param){
		$this->excludeParameters[] = $param;
	}

	/**
	 * Returns the base string of this request
	 *
	 * The base string defined as the method, the url
	 * and the parameters (normalized), each url-encoded
	 * and the concatenated with &.
	 */
	public function getSignatureBaseString()
	{
		$parts = array(
			$this->getNormalizedHttpMethod(),
			$this->getNormalizedHttpUrl(),
			$this->getSignableParameters()
		);

		$parts = Util::urlEncodeRfc3986($parts);

		return implode('&', $parts);
	}

	/**
	 * just uppercase's the http method
	 */
	public function getNormalizedHttpMethod()
	{
		return strtoupper($this->httpMethod);
	}

	/**
	 * parses the url and rebuilds it to be
	 * scheme://host/path
	 */
	public function getNormalizedHttpUrl()
	{
		$parts = parse_url($this->httpUrl);

		$scheme = $parts['scheme'];
		if (isset($parts['port'])) {
			$port = @$parts['port'];
		} else {
			$port = ($scheme == 'https') ? '443' : '80';
		}
		$host = $parts['host'];
		$path = @$parts['path'];

		if (($scheme == 'https' && $port != '443')
			|| ($scheme == 'http' && $port != '80')
		) {
			$host = "$host:$port";
		}
		return "$scheme://$host$path";
	}

	/**
	 * builds a url usable for a GET request
	 * @return string
	 */
	public function toUrl()
	{
		$postData = $this->toPostData();
		$out = $this->getNormalizedHttpUrl();
		if ($postData) {
			$out .= '?' . $postData;
		}
		return $out;
	}

	/**
	 * builds the data one would send in a POST request
	 * @return string
	 */
	public function toPostData()
	{
		return Util::buildHttpQuery($this->parameters);
	}

	/**
	 * builds the Authorization: header
	 * @param string|null $realm
	 * @throws Exception\OAuthException
	 * @return string
	 */
	public function toHeader($realm = null)
	{
		if ($realm)
			$out = 'Authorization: OAuth realm="' . Util::urlEncodeRfc3986($realm) . '"';
		else
			$out = 'Authorization: OAuth';

		foreach ($this->parameters as $k => $v) {
			if (substr($k, 0, 5) != "oauth") continue;
			if (is_array($v)) {
				throw new Exception\OAuthException('Arrays not supported in headers');
			}
			$out .= ',' .
				Util::urlEncodeRfc3986($k) .
				'="' .
				Util::urlEncodeRfc3986($v) .
				'"';
		}
		return $out;
	}

	/**
	 * @return string
	 */
	public function __toString()
	{
		return $this->toUrl();
	}


	/**
	 * @param Consumer $consumer
	 * @param Token|null $token
	 */
	public function signRequest(Consumer $consumer, Token $token = null)
	{
		$this->setParameter(
			"oauth_signature_method",
			$consumer->signatureMethod->getName(),
			false
		);
		$signature = $consumer->signatureMethod->buildSignature($this, $consumer, $token);
		$this->setParameter("oauth_signature", $signature, false);
	}

	/**
	 * util function: current timestamp
	 * @return int
	 */
	private static function generateTimestamp()
	{
		return time();
	}

	/**
	 * util function: current nonce
	 * @return string
	 */
	private static function generateNonce()
	{
		$mt = microtime();
		$rand = mt_rand();

		return md5($mt . $rand); // md5s look nicer than numbers
	}
}