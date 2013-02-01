<?php

namespace Ndm\OAuth;
/**
 *
 */
class Consumer
{
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
	 * @var string|null
	 */
	public $host;

	/**
	 * @var SignatureMethod\SignatureMethodInterface
	 */
	public $signatureMethod;


	/**
	 * @param string $key
	 * @param string $secret
	 * @param SignatureMethod\SignatureMethodInterface $signatureMethod
	 * @param int|null $userId if provided, allows the consumer to be used as 2-legged endpoint
	 * @param string|null $host
	 */
	public function __construct($key, $secret, SignatureMethod\SignatureMethodInterface $signatureMethod, $userId=null, $host=null)
	{
		$this->key = $key;
		$this->secret = $secret;
		$this->signatureMethod = $signatureMethod;
		$this->userId = $userId;
		$this->host = $host;
	}

	/**
	 * @return string
	 */
	public function __toString()
	{
		return "Consumer[key={$this->key},secret={$this->secret},user_id={$this->userId}]";
	}

	/**
	 *  @return bool
	 */
	public function is2LeggedAccess(){
		return !empty($this->userId);
	}

	/**
	 * @return bool
	 */
	public function is3LeggedAccess(){
		return empty($this->userId);
	}

	/**
	 * @param string $ipAddress
	 * @return bool
	 */
	public function checkHost($ipAddress){
		if ($this->host === null){
			return true;
		} else {
			return Util::networkMatch($this->host,$ipAddress);
		}
	}
}