<?php
namespace geocata\auth\jwt;

use geocata\auth\jwt\algorithm;
use geocata\auth\jwt\exception;

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
class Jwt {
	/**
	 * The header object
	 *
	 * @var array
	 * @access protected
	 */
	protected $header = array();
	
	/**
	 * The claims object
	 *
	 * @var array
	 * @access protected
	 */
	protected $claims = array();
	
	/**
	 * The JWT as a string, ready to be used for auth
	 *
	 * @var string
	 * @access protected
	 */
	protected $jwtAuthReadyString;
	
	const CLOCK_SKEW = 1200;
	
	private function __construct() {
		
	}
	
	/**
	 * @param array $header
	 * @param array $claims
	 * @param array $allowedAlgorithms
	 * @param algorithm\AbstractCryptography $cryptography
	 *
	 * @return static
	 * @throws exception\JwtSigningException
	 * @throws \Exception
	 *
	 * @access public
	 * @since Method/function available since Release 1.0
	 */
	public static function buildWithNewClaims(
			array $header, 
			array $claims, 
			algorithm\AbstractCryptography $cryptography) {
		$self = new static();
		$self->header = $header;
		$self->claims = $claims;
		
		$headerJsonStr = json_encode($header);
		$claimsJsonStr = json_encode($claims);
		
		if($headerJsonStr === FALSE || $claimsJsonStr === FALSE) {
			throw new \Exception('Could not encode header or claims to json.');
		}
		
		$elementToSign = $self->urlsafeB64Encode($headerJsonStr) 
				. '.' . $self->urlsafeB64Encode($claimsJsonStr);
		
		$signature = $self->urlsafeB64Encode($cryptography->sign($elementToSign));
		
		$self->jwtAuthReadyString = $elementToSign . '.' . $signature;
		
		return $self;
	}
	
	/**
	 * Build new jswt form given claims
	 * 
	 * @param string $jwtSignedString
	 *
	 * @return static
	 * @throws \InvalidArgumentException
	 * @throws exception\InvalidJwtSignatureException
	 * @throws \Exception
	 *
	 * @static
	 * @access public
	 * @since Method/function available since Release 1.0
	 */
	public static function buildFromClaims($jwtSignedString) {
		if(!is_string($jwtSignedString)) {
			throw new \InvalidArgumentException('The signed jwt string is malformed. Invalid format.');
		}
		
		$self = new static();
		
		$encodedParts = explode('.', $jwtSignedString);
		
		if(count($encodedParts) !== 3) {
			throw new \InvalidArgumentException('The signed jwt string is malformed. Incorect number'
					. ' of elements.');
		}
		
		$self->header = $self->jsonDecode($self->urlsafeB64Decode($encodedParts[0]));
		$self->claims = $self->jsonDecode($self->urlsafeB64Decode($encodedParts[1]));
		$self->jwtAuthReadyString = $jwtSignedString;
		
		if(!is_array($self->header) || !is_array($self->claims)) {
			throw new \InvalidArgumentException('The signed jwt string is malformed.'
					. ' Unable to decode the elements.');
		}
		
		if(empty($self->header['typ']) || empty($self->header['alg']) 
				|| strtolower($self->header['typ']) !== 'jwt') {
			throw new \InvalidArgumentException('The signed jwt string is malformed.'
					. ' Header elements are invalid.');
		}
		
		// Check if the nbf if it is defined. This is the time that the
        // token can actually be used. If it's not yet that time, abort.
		// Use self clock skew constnat as leeway
        if (array_key_exists('nbf', $self->claims) && $self->claims['nbf'] > (time() + self::CLOCK_SKEW)) {
            throw new exception\InvalidJwtSignatureException(
                'Cannot handle JWT prior to ' . date(\DateTime::ISO8601, $self->claims['nbf'])
            );
        }

        // Check that this token has been created before 'now'. This prevents
        // using tokens that have been created for later use (and haven't
        // correctly used the nbf claim).
		// Use self clock skew constnat as leeway
        if (array_key_exists('iat', $self->claims) && $self->claims['iat'] > (time() + self::CLOCK_SKEW)) {
            throw new exception\InvalidJwtSignatureException(
                'Cannot handle JWT prior to ' . date(\DateTime::ISO8601, $self->claims['iat'])
            );
        }

        // Check if this token has expired.
		// Use self clock skew constnat as leeway
        if (array_key_exists('exp', $self->claims) && (time() - self::CLOCK_SKEW) >= $self->claims['exp']) {
            throw new exception\InvalidJwtSignatureException('Expired JWT');
        }
		
		return $self;
	}
	
	/**
	 * Verify the claims
	 * 
	 * @param algorithm\AbstractCryptography[] $allowedCryptography What cryptography should be allowed
	 *																for the client to use for auth
	 *
	 * @return void
	 * @throws exception\InvalidJwtSignatureException
	 *
	 * @access public
	 * @since Method/function available since Release 1.0
	 */
	public function verify(array $allowedCryptography) {
		$encodedParts = explode('.', $this->jwtAuthReadyString);
		
		$rawSignature = $this->urlsafeB64Decode($encodedParts[2]);
		
		if($rawSignature === FALSE) {
			throw new \InvalidJwtSignatureException('The signed jwt string is malformed.'
					. ' Unable to decode the elements.');
		}
		
		$cryptoToUse = NULL;
		
		foreach($allowedCryptography as $crypto) {
			if(strtolower($crypto->getJwtAlgo()) === strtolower($this->header['alg'])) {
				$cryptoToUse = $crypto;
				break;
			}
		}
		
		if($cryptoToUse === NULL) {
			throw new \InvalidJwtSignatureException('Invalid jwt, algorithm not allowed.');
		}
		
		$cryptoToUse->verify(
				$encodedParts[0] . '.' . $encodedParts[1], 
				$rawSignature);
	}
	
	/**
	 * 
	 * @return array
	 */
	public function getHeader() {
		return $this->header;
	}

	/**
	 * 
	 * @return array
	 */
	public function getClaims() {
		return $this->claims;
	}

	/**
	 * 
	 * @return string
	 */
	public function getJwtAuthReadyString() {
		return $this->jwtAuthReadyString;
	}

    /**
     * Decode a string with URL-safe Base64.
     *
     * @param string $input A Base64 encoded string
     *
     * @return string|bool A decoded string. False on failure
     */
    public function urlsafeB64Decode($input) {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * Encode a string with URL-safe Base64.
     *
     * @param string $input The string you want encoded
     *
     * @return string|bool The base64 encode of what you passed in. False on failure
     */
    public function urlsafeB64Encode($input) {
		$encoded = base64_encode($input);
		
		if($encoded === FALSE) {
			return FALSE;
		}
		
        return str_replace('=', '', strtr($encoded, '+/', '-_'));
    }
	
	/**
	 * Decode a JSON string into a PHP object.
	 *
	 * @param string $input JSON string
	 *
	 * @return array Array representation of JSON string
	 */
	public function jsonDecode($input) {
		return json_decode($input, TRUE, 512, JSON_BIGINT_AS_STRING);
	}
}

?>
