<?php
namespace geocata\auth\jwt\algorithm;

use geocata\auth\jwt\exception\JwtSigningException;
use geocata\auth\jwt\exception\InvalidJwtSignatureException;

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
abstract class AbstractHsCryptography extends AbstractCryptography {
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
    public function __construct($key) {
        $this->key = $key;
    }
    
    /**
     * Sign a message
     * 
     * @param string $message
     *
     * @return string Binary string. The raw output
     * @throws JwtSigningException If the signing failed
     *
     * @access public
     * @since Method/function available since Release 1.0
     */
    public function sign($message) {
        $res = @hash_hmac($this->getHashAlgo(), $message, $this->key, TRUE);
        
        if($res === FALSE) {
            throw new JwtSigningException('Failed to generate keyed hash value using HMAC.');
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
     * @throws InvalidJwtSignatureException Throws exceptions if verification failed for some reason
     *
     * @access public
     * @since Method/function available since Release 1.0
     */
    public function verify($originalMessage, $userSignedMessage) {
        $hash = $this->sign($originalMessage);
        
        if($this->equals($hash, $userSignedMessage) === FALSE) {
            throw new InvalidJwtSignatureException('Could not verify the user provided message.'
                    . ' Invalid signature.');
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

?>
