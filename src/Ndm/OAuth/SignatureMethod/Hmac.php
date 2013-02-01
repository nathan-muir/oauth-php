<?php
namespace Ndm\OAuth\SignatureMethod;

/**
 * The HMAC-SHA1 signature method uses the HMAC-SHA1 signature algorithmrithm as defined in [RFC2104]
 * where the Signature Base String is the text and the key is the concatenated values (each first
 * encoded per Parameter Encoding) of the Consumer Secret and Token Secret, separated by an '&'
 * character (ASCII code 38) even if empty.
 *   - Chapter 9.2 ("HMAC-SHA1")
 */
class Hmac implements SignatureMethodInterface
{
    /**@#+
     * @const HMAC algorithms supported
     */
    const ALGORITHM_SHA1 = 'sha1';
    /**
     *
     */
    const ALGORITHM_SHA224 = 'sha224';
    /**
     *
     */
    const ALGORITHM_SHA256 = 'sha256';
    /**
     *
     */
    const ALGORITHM_SHA384 = 'sha384';
    /**
     *
     */
    const ALGORITHM_SHA512 = 'sha512';

    /**
     * @var string
     */
    private $algorithm;

    /**
     * @param string $algorithm
     */
    public function __construct($algorithm = self::ALGORITHM_SHA1)
    {
        $this->algorithm = $algorithm;
    }

    /**
     * @return string
     */
    public function getName()
    {
        return "HMAC-" . strtoupper($this->algorithm);
    }

    /**
     * @param \Ndm\OAuth\Request $request
     * @param \Ndm\OAuth\Consumer $consumer
     * @param \Ndm\OAuth\Token $token
     * @return string
     */
    public function buildSignature(
        \Ndm\OAuth\Request $request,
        \Ndm\OAuth\Consumer $consumer,
        \Ndm\OAuth\Token $token = null
    ) {
        $base_string = $request->getSignatureBaseString();
        $request->baseString = $base_string;

        $keyParts = array(
            $consumer->secret,
            ($token) ? $token->secret : ""
        );

        $keyParts = \Ndm\OAuth\Util::urlEncodeRfc3986($keyParts);
        $key = implode('&', $keyParts);

        return base64_encode(hash_hmac($this->algorithm, $base_string, $key, true));
    }

    /**
     * Verifies that a given signature is correct
     * @param \Ndm\OAuth\Request $request
     * @param \Ndm\OAuth\Consumer $consumer
     * @param \Ndm\OAuth\Token $token
     * @param string $signature
     * @return bool
     */
    public function checkSignature(
        \Ndm\OAuth\Request $request,
        \Ndm\OAuth\Consumer $consumer,
        \Ndm\OAuth\Token $token = null,
        $signature = ''
    ) {
        $built = $this->buildSignature($request, $consumer, $token);
        return $built == $signature;
    }

}