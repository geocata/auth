<?php
namespace geocata\auth\jwt\algorithm;

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
class RS256Cryptography extends AbstractRsCryptography {
	/**
	 * The hash algo used internally by the hash function
	 *
	 * @var string
	 * @const
	 * @access public
	 */
	const INTERNAL_ALGORITHM =  OPENSSL_ALGO_SHA256;
	
	/**
	 * The jwt algorithm name
	 *
	 * @var string
	 * @const
	 * @access public
	 */
	const JWT_ALGORITHM = 'RS256';
	
	/**
	 * Get the hash algorithm to be used by the hashing function
	 *
	 * @return string The hash algorithm used by the mac hashing php function
	 * @throws --
	 *
	 * @access protected
	 * @since Method/function available since Release 1.0
	 */
	protected function getHashAlgo() {
		return self::INTERNAL_ALGORITHM;
	}
	
	/**
	 * Get the jwt algo that is used by this crypto class
	 *
	 * @return string
	 * @throws --
	 * 
	 * @access public
	 * @since Method/function available since Release 1.0
	 */
	public function getJwtAlgo() {
		return self::JWT_ALGORITHM;
	}
}

?>
