<?php

namespace geocata\auth\jwt\algorithm;

use geocata\auth\jwt\exception\IncompatibleEnvironment;
use geocata\auth\jwt\exception\InvalidJwtSignature;
use geocata\auth\jwt\exception\JwtSigningFailed;

/**
 *
 * Short description 
 *
 * Long description 
 *
 * @category   --
 * @package    --
 * @license    --
 * @version    1.0
 * @link       --
 * @since      Class available since Release 1.0
 */
abstract class AbstractRsCryptography extends AbstractCryptography
{
    /**
     * The public key to be used for verifying a signature
     *
     * @var resource
     * @access protected
     */
    protected $publicKey = NULL;

    /**
     * The private key to be used for signing a message
     *
     * @var resource
     * @access protected
     */
    protected $privateKey = NULL;

    /**
     * Construct
     * 
     * @param string $privateKey The pem formatted private key
     * @param string $publicKey The pem formatted public key
     * @param string $passPhrase The passphrase used to encrypt/decrypt the private key
     * 
     * @throws \InvalidArgumentException If any of the keys are invalid
     * @throws IncompatibleEnvironment
     *
     * @access public
     * @since Method/function available since Release 1.0
     */
    public function __construct($privateKey = NULL, $publicKey = NULL, $passPhrase = NULL)
    {
        $this->checkEnvCompatibility();

        if ($privateKey === NULL && $publicKey === NULL) {
            throw new \InvalidArgumentException('At least one of the keys must be provided.');
        }

        if ($privateKey !== NULL) {
            $this->privateKey = openssl_pkey_get_private($privateKey, $passPhrase);

            if ($this->privateKey === FALSE) {
                throw new \InvalidArgumentException('Invalid private key.');
            }
        }

        if ($publicKey !== NULL) {
            $this->publicKey = openssl_pkey_get_public($publicKey);

            if ($this->publicKey === FALSE) {
                throw new \InvalidArgumentException('Invalid public key.');
            }
        }
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
        $signature = '';
        $success = @openssl_sign($message, $signature, $this->privateKey, $this->getHashAlgo());

        if (!$success) {
            throw new JwtSigningFailed('OpenSSL unable to sign data : ' . openssl_error_string());
        }
        else {
            return $signature;
        }
    }

    /**
     * Verify if the user provided message complies with the original message
     * 
     * @param string $originalMessage
     * @param string $userSignedMessage
     *
     * @return void Does not return anything. Throws exceptions if verification failed for some reason
     * @throws InvalidJwtSignature
     *
     * @access public
     * @since Method/function available since Release 1.0
     */
    public function verify($originalMessage, $userSignedMessage)
    {
        $success = @openssl_verify(
                        $originalMessage,
                        $userSignedMessage,
                        $this->publicKey,
                        $this->getHashAlgo());

        if (!$success) {
            throw new InvalidJwtSignature(
                    'OpenSSL unable to verify data: ' . openssl_error_string());
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

    /**
     * Verify if the cryptography will work or not in caller's environment
     *
     * @return void
     * @throws IncompatibleEnvironment
     *
     * @access public
     * @since Method/function available since Release 1.0
     */
    protected function checkEnvCompatibility()
    {
        if (!function_exists('openssl_pkey_get_public')
                || !function_exists('openssl_pkey_get_private')
                || !function_exists('openssl_sign')
                || !function_exists('openssl_verify')) {
            throw new IncompatibleEnvironment(
                    'Jwt library requires openssl extension in order' 
                    . 'to work with RS* types of algorithms.');
        }
    }

}