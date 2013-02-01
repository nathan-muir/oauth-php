<?php
namespace Ndm\OAuth;

/**
 * access tokens and request tokens
 */
class Token
{

	/**@#+
	 * @const Token types
	 */
	const TYPE_REQUEST = "request";
    /**
     *
     */
    const TYPE_ACCESS = "access";

	/**
	 * @var string
	 */
	public $key;
	/**
	 * @var string
	 */
	public $secret;

	/**
	 * @var int|null
	 */
	public $userId;

	/**
	 * @param string $key the token
	 * @param string $secret the token secret
	 * @param int|null $userId
	 */
	function __construct($key, $secret, $userId=null)
	{
		$this->key = $key;
		$this->secret = $secret;
		$this->userId = $userId;
	}

	/**
	 * generates the basic string serialization of a token that a server
	 * would respond to request_token and access_token calls with
	 * @return string
	 */
	function to_string()
	{
		return "oauth_token=" .
			Util::urlEncodeRfc3986($this->key) .
			"&oauth_token_secret=" .
			Util::urlEncodeRfc3986($this->secret);
	}

	/**
	 * @return string
	 */
	function __toString()
	{
		return $this->to_string();
	}
}