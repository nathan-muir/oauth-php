<?php
namespace Ndm\OAuth\SignatureMethod;

/**
 * The PLAINTEXT method does not provide any security protection and SHOULD only be used
 * over a secure channel such as HTTPS. It does not use the Signature Base String.
 *   - Chapter 9.4 ("PLAINTEXT")
 */
class Plaintext implements SignatureMethodInterface
{
    /**
     * @return string
     */
    public function getName()
    {
        return "PLAINTEXT";
    }

    /**
     * oauth_signature is set to the concatenated encoded values of the Consumer Secret and
     * Token Secret, separated by a '&' character (ASCII code 38), even if either secret is
     * empty. The result MUST be encoded again.
     *   - Chapter 9.4.1 ("Generating Signatures")
     *
     * Please note that the second encoding MUST NOT happen in the SignatureMethod, as
     * Request handles this!
     *
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
        $keyParts = array(
            $consumer->secret,
            ($token) ? $token->secret : ""
        );

        $keyParts = \Ndm\OAuth\Util::urlEncodeRfc3986($keyParts);
        $key = implode('&', $keyParts);
        $request->baseString = $key;

        return $key;
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