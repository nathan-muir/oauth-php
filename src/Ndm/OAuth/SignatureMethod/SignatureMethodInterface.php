<?php
namespace Ndm\OAuth\SignatureMethod;

/**
 * A class for implementing a Signature Method
 * See section 9 ("Signing Requests") in the spec
 */
interface SignatureMethodInterface
{
    /**
     * Needs to return the name of the Signature Method (ie HMAC-SHA1)
     * @return string
     */
    public function getName();

    /**
     * Build up the signature
     * NOTE: The output of this function MUST NOT be urlencoded.
     * the encoding is handled in Request when the final
     * request is serialized
     * @param \Ndm\OAuth\Request $request
     * @param \Ndm\OAuth\Consumer $consumer
     * @param \Ndm\OAuth\Token $token
     * @return string
     */
    public function buildSignature(
        \Ndm\OAuth\Request $request,
        \Ndm\OAuth\Consumer $consumer,
        \Ndm\OAuth\Token $token = null
    );

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
    );
}