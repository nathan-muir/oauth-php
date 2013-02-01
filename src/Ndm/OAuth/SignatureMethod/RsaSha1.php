<?php

namespace Ndm\OAuth\SignatureMethod;

/**
 * The RSA-SHA1 signature method uses the RSASSA-PKCS1-v1_5 signature algorithm as defined in
 * [RFC3447] section 8.2 (more simply known as PKCS#1), using SHA-1 as the hash function for
 * EMSA-PKCS1-v1_5. It is assumed that the Consumer has provided its RSA public key in a
 * verified way to the Service Provider, in a manner which is beyond the scope of this
 * specification.
 *   - Chapter 9.3 ("RSA-SHA1")
 */
class RsaSha1 implements SignatureMethodInterface
{
    /**
     * @return string
     */
    public function getName()
    {
        return "RSA-SHA1";
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
        $baseString = $request->getSignatureBaseString();
        $request->baseString = $baseString;

        // Pull the private key ID from the certificate
        $privateKeyId = openssl_get_privatekey($consumer->secret);

        // Sign using the key
        openssl_sign($baseString, $signature, $privateKeyId);

        // Release the key resource
        openssl_free_key($privateKeyId);

        return base64_encode($signature);
    }

    /**
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
        $decodedSig = base64_decode($signature);

        $baseString = $request->getSignatureBaseString();

        // Pull the public key ID from the certificate
        $publicKeyId = openssl_get_publickey($consumer->secret);

        // Check the computed signature against the one passed in the query
        $ok = openssl_verify($baseString, $decodedSig, $publicKeyId);

        // Release the key resource
        openssl_free_key($publicKeyId);

        return $ok == 1;
    }
}