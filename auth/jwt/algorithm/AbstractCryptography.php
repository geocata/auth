<?php

namespace geocata\auth\jwt\algorithm;

use geocata\auth\jwt\exception\JwtSigningFailed;
use geocata\auth\jwt\exception\InvalidJwtSignature;

/**
 *
 * @author George Catalin
 */
abstract class AbstractCryptography
{

    /**
     * Sign a message
     * 
     * @param string $message
     *
     * @return string
     * @throws JwtSigningFailed If the signing failed
     *
     * @abstract
     * @access public
     * @since Method/function available since Release 1.0
     */
    abstract public function sign($message);

    /**
     * Verify if the user provided message complies with the original message
     * 
     * @param string $originalMessage
     * @param string $userSignedMessage
     *
     * @return void Does not return anything
     * @throws InvalidJwtSignature Throws exceptions if verification failed for some reason
     *
     * @abstract
     * @access public
     * @since Method/function available since Release 1.0
     */
    abstract public function verify($originalMessage, $userSignedMessage);

    /**
     * Compares two strings.
     *
     * This method implements a constant-time algorithm to compare strings.
     *
     * @param string $knownString The string of known length to compare against
     * @param string $userInput   The string that the user can control
     *
     * @return bool True if the two strings are the same, false otherwise
     * 
     * @access protected
     * @since Method/function available since Release 1.0
     */
    protected function equals($knownString, $userInput)
    {
        return hash_equals($knownString, $userInput);
    }

    /**
     * Get the jwt algo that is used by this crypto class
     *
     * @return string
     * @throws --
     *
     * @abstract
     * @access public
     * @since Method/function available since Release 1.0
     */
    abstract public function getJwtAlgo();
}