<?php

namespace rsgcata\auth\jwt\algorithm;

use rsgcata\auth\jwt\exception\JwtSigningFailed;
use rsgcata\auth\jwt\exception\InvalidJwtSignature;

/**
 * @author George Catalin
 */
abstract class AbstractHsCryptography extends AbstractCryptography
{
    /**
     * The key to be used for cryptography
     *
     * @var string
     * @access protected
     */
    protected $key;

    /**
     * Construct
     * 
     * @param string $key
     * 
     * @throws --
     *
     * @access public
     * @since Method/function available since Release 1.0
     */
    public function __construct($key)
    {
        $this->key = $key;
    }

    /**
     * Sign a message
     * 
     * @param string $message
     *
     * @return string Binary string. The raw output
     * @throws JwtSigningFailed If the signing failed
     *
     * @access public
     * @since Method/function available since Release 1.0
     */
    public function sign($message)
    {
        $res = @hash_hmac($this->getHashAlgo(), $message, $this->key, TRUE);

        if ($res === FALSE) {
            throw new JwtSigningFailed('Failed to generate keyed hash value using HMAC.');
        }

        return $res;
    }

    /**
     * Verify if the user provided message complies with the original message
     * 
     * @param string $originalMessage
     * @param string $userSignedMessage As binary string
     *
     * @return void Does not return anything
     * @throws InvalidJwtSignature Throws exceptions if verification failed for some reason
     *
     * @access public
     * @since Method/function available since Release 1.0
     */
    public function verify($originalMessage, $userSignedMessage)
    {
        $hash = $this->sign($originalMessage);

        if ($this->equals($hash, $userSignedMessage) === FALSE) {
            throw new InvalidJwtSignature(
                    'Could not verify the user provided message. Invalid signature.');
        }
    }

    /**
     * Get the hash algorithm to be used by the hashing function
     *
     * @return string The hash algorithm used by the mac hashing php function
     * @throws --
     *
     * @access protected
     * @since Method/function available since Release 1.0
     */
    abstract protected function getHashAlgo();
}