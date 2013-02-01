<?php
namespace Ndm\OAuth\DataStore;



/**
 *
 */
interface DataStoreInterface
{
	/**
	 * @param string $consumerKey
	 * @return \Ndm\OAuth\Consumer
	 */
	public function lookupConsumer($consumerKey);

	/**
	 * @param \Ndm\OAuth\Consumer $consumer
	 * @param string $tokenType
	 * @param string $token
	 * @return \Ndm\OAuth\Token
	 */
	public function lookupToken(\Ndm\OAuth\Consumer $consumer, $tokenType, $token);

	/**
	 * @param \Ndm\OAuth\Consumer $consumer
	 * @param \Ndm\OAuth\Token $token
	 * @param string $nonce
	 * @param int $timestamp
	 * @return bool
     */
	public function lookupNonce(\Ndm\OAuth\Consumer $consumer, \Ndm\OAuth\Token $token, $nonce, $timestamp);

	/**
	 * @param \Ndm\OAuth\Consumer $consumer
	 * @param string|null $callback
	 * @return \Ndm\OAuth\Token
	 */
	public function newRequestToken(\Ndm\OAuth\Consumer $consumer, $callback = null);

	/**
	 * @param \Ndm\OAuth\Token $token
	 * @param \Ndm\OAuth\Consumer $consumer
	 * @param null|string $verifier
	 * @return \Ndm\OAuth\Token
	 */
	public function newAccessToken(\Ndm\OAuth\Token $token, \Ndm\OAuth\Consumer $consumer, $verifier = null);
	// return a new access token attached to this consumer
	// for the user associated with this token if the request token
	// is authorized
	// should also invalidate the request token

}