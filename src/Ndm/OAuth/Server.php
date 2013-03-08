<?php
namespace Ndm\OAuth;

/**
 *
 */
class Server
{
	/**
	 * @var int
	 */
	protected $timestampThreshold = 300;
	/**
	 * @var string
	 */
	protected $version = '1.0';

	/**
	 * @var DataStore\DataStoreInterface
	 */
	protected $dataStore;

	/**
	 * @param DataStore\DataStoreInterface $dataStore
	 */
	function __construct(DataStore\DataStoreInterface $dataStore)
	{
		$this->dataStore = $dataStore;
	}

	/**
	 * process a request_token request
	 * returns the request token on success
	 * @param Request $request
	 * @throws Exception\BadRequestException
	 * @throws Exception\UnauthorisedException
	 * @return Token
	 */
	public function fetchRequestToken(Request $request)
	{
		$this->getVersion($request);

		$consumer = $this->getConsumer($request);
		if (!$consumer->is3LeggedAccess()){ //FIXME currently allows 'Gateway' access applications
			throw new Exception\UnauthorisedException("The provided consumer does not have token access.");
		}
		if($request->remoteAddress !== null && !$consumer->checkHost($request->remoteAddress)){
			throw new Exception\BadRequestException("Access not allowed from host");
		}

		// no token required for the initial token request
		$token = null;

		$this->checkSignature($request, $consumer, $token);

		// Rev A change
		$callback = $request->getParameter('oauth_callback');
		if ($callback === null){
			throw new Exception\BadRequestException("Parameter missing- oauth_callback");
		}
		$new_token = $this->dataStore->newRequestToken($consumer, $callback);

		return $new_token;
	}

	/**
	 * process an access_token request
	 * returns the access token on success
	 * @param Request $request
	 * @throws Exception\BadRequestException
	 * @throws Exception\UnauthorisedException
	 * @return Token
	 */
	public function fetchAccessToken(Request $request)
	{
		$this->getVersion($request);

		$consumer = $this->getConsumer($request);

		if($request->remoteAddress !== null && !$consumer->checkHost($request->remoteAddress)){
			throw new Exception\UnauthorisedException("Unauthorised Access");
		}

		// requires authorized request token
		$token = $this->getToken($request, $consumer, Token::TYPE_REQUEST);

		$this->checkSignature($request, $consumer, $token);

		// Rev A change
		$verifier = $request->getParameter('oauth_verifier');
		if($verifier === null){
			throw new Exception\BadRequestException("Parameter missing- oauth_verifier");
		}
		$new_token = $this->dataStore->newAccessToken($token, $consumer, $verifier);

		return $new_token;
	}

	/**
	 * verify an api call, checks all the parameters
	 *
	 * @param Request $request
	 * @throws Exception\OAuthException
	 * @throws Exception\UnauthorisedException
	 * @return array
	 *
	 */
	public function verifyRequest(Request $request)
	{
		$this->getVersion($request);
		$consumer = $this->getConsumer($request);

		if($request->remoteAddress !== null && !$consumer->checkHost($request->remoteAddress)){
			throw new Exception\UnauthorisedException("Unauthorised Access");
		}

		$token = null;
		if ($consumer->is3LeggedAccess()){ //FIXME currently allows 'Gateway' access applications
			$token = $this->getToken($request, $consumer, Token::TYPE_ACCESS);
		}
		$this->checkSignature($request, $consumer, $token);
		return array($consumer, $token);
	}

	/**
	 * version 1
	 * @param Request $request
	 * @throws Exception\BadRequestException
	 * @return string
	 */
	private function getVersion(Request $request)
	{
		$version = $request->getParameter("oauth_version");
		if (!$version) {
			// Service Providers MUST assume the protocol version to be 1.0 if this parameter is not present.
			// Chapter 7.0 ("Accessing Protected Resources")
			$version = '1.0';
		}
		if ($version !== $this->version) {
			throw new Exception\BadRequestException("OAuth version '$version' not supported");
		}
		return $version;
	}

	/**
	 * try to find the consumer for the provided request's consumer key
	 * @param Request $request
	 * @throws Exception\UnauthorisedException
	 * @throws Exception\BadRequestException
	 * @return Consumer
	 */
	private function getConsumer(Request $request)
	{
		$consumer_key = @$request->getParameter("oauth_consumer_key");
		if (!$consumer_key) {
			throw new Exception\BadRequestException("Parameter missing- oauth_consumer_key");
		}

		$consumer = $this->dataStore->lookupConsumer($consumer_key);
		if (!$consumer) {
			throw new Exception\UnauthorisedException("Invalid consumer");
		}

		return $consumer;
	}

	/**
	 * try to find the token for the provided request's token key
	 * @param Request $request
	 * @param Consumer $consumer
	 * @param string $token_type
	 * @throws Exception\UnauthorisedException
	 * @throws Exception\BadRequestException
	 * @return Token
	 */
	private function getToken(Request $request, Consumer $consumer, $token_type)
	{
		$token_field = @$request->getParameter('oauth_token');
		if (!$token_field){
			throw new Exception\BadRequestException("Parameter missing- oauth_token");
		}
		$token = $this->dataStore->lookupToken(
			$consumer, $token_type, $token_field
		);
		if (!$token) {
			throw new Exception\UnauthorisedException("Invalid $token_type token: $token_field");
		}
		return $token;
	}


	/**
	 * all-in-one function to check the signature on a request
	 * should guess the signature method appropriately
	 *
	 * @param Request  $request
	 * @param Consumer $consumer
	 * @param Token    $token
	 *
	 * @throws Exception\BadRequestException
	 * @throws Exception\UnauthorisedException
	 */
	private function checkSignature(Request $request, Consumer $consumer, $token)
	{
		// this should probably be in a different method
		$timestamp = @$request->getParameter('oauth_timestamp');
		$nonce = @$request->getParameter('oauth_nonce');

		$this->checkTimestamp($timestamp);
		$this->checkNonce($consumer, $token, $nonce, $timestamp);


		$request_signature_method =
			@$request->getParameter("oauth_signature_method");

		if (!$request_signature_method) {
			// According to chapter 7 ("Accessing Protected Ressources") the signature-method
			// parameter is required, and we can't just fallback to PLAINTEXT
			throw new Exception\BadRequestException('No signature method parameter. This parameter is required');
		}

		if (strcmp($request_signature_method, $consumer->signatureMethod->getName()) !== 0) {
			throw new Exception\BadRequestException(
				"Signature method '$request_signature_method' is not supported for this consumer"
			);
		}

		$signature = $request->getParameter('oauth_signature');
		$valid_sig = $consumer->signatureMethod->checkSignature(
			$request,
			$consumer,
			$token,
			$signature
		);

		if (!$valid_sig) {
			throw new Exception\UnauthorisedException("Invalid signature");
		}
	}

	/**
	 * check that the timestamp is new enough
	 * @param int $timestamp
	 * @throws Exception\BadRequestException
	 * @throws Exception\UnauthorisedException
	 */
	private function checkTimestamp($timestamp)
	{
		if (!$timestamp)
			throw new Exception\BadRequestException(
				'Missing timestamp parameter. The parameter is required'
			);

		// verify that timestamp is recentish
		$now = time();
		if (abs($now - $timestamp) > $this->timestampThreshold) {
			throw new Exception\UnauthorisedException(
				"Expired timestamp, yours $timestamp, ours $now"
			);
		}
	}

	/**
	 * check that the nonce is not repeated
	 * @param Consumer $consumer
	 * @param Token $token
	 * @param string $nonce
	 * @param int $timestamp
	 * @throws Exception\BadRequestException
	 * @throws Exception\UnauthorisedException
	 */
	private function checkNonce(Consumer $consumer, Token $token=null, $nonce='', $timestamp=0)
	{
		if (!$nonce)
			throw new Exception\BadRequestException(
				'Missing nonce parameter. The parameter is required'
			);

		// verify that the nonce is uniqueish
		$found = $this->dataStore->lookupNonce(
			$consumer,
			$token,
			$nonce,
			$timestamp
		);
		if ($found) {
			throw new Exception\UnauthorisedException("Nonce already used: $nonce");
		}
	}

}