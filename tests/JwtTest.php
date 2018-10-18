<?php
namespace tests;

use geocata\auth\jwt\Jwt;
use geocata\auth\jwt\algorithm\HS256Cryptography;
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
class JwtTest extends \PHPUnit\Framework\TestCase {
	private $algo;
	private $header;
	private $claims;
	
	/**
	 * @return void
	 */
	protected function setUp() {
		$this->algo = new HS256Cryptography('aKey');
		$this->header = ['alg' => HS256Cryptography::JWT_ALGORITHM, 'typ' => 'jwt'];
		$this->claims = ['usr' => 'test', 'msg' => 'amsg'];
	}

	public function testBuildWithNewClaimsWorks() {
		$jwt = Jwt::buildWithNewClaims($this->header, $this->claims, $this->algo);
		
		$this->assertNotEmpty($jwt->getJwtAuthReadyString());
	}
	
	public function testBuildWithNewClaimsFailsWhenInvalidJson() {
		$fp = fopen(__DIR__ . DIRECTORY_SEPARATOR . 'algorithm' . DIRECTORY_SEPARATOR 
				. 'AbstractHsCryptographyTest.php', 'r');
		$this->claims['invalid'] = $fp;
		
		$this->expectException(\Exception::class);
		$this->expectExceptionMessage('Could not encode header');
		
		Jwt::buildWithNewClaims($this->header, $this->claims, $this->algo);
		fclose($fp);
	}
	
	/**
	 * @depends testBuildWithNewClaimsWorks
	 */
	public function testBuildFromClaimsWorks() {
		$jwt = Jwt::buildWithNewClaims($this->header, $this->claims, $this->algo);
		
		$jwt2 = Jwt::buildFromClaims($jwt->getJwtAuthReadyString());
		
		$this->assertEquals($this->header, $jwt2->getHeader());
		$this->assertEquals($this->claims, $jwt2->getClaims());
	}
	
	public function buildFromClaimsFailDataProvider() {
		$this->setUp();
		$jwt = Jwt::buildWithNewClaims($this->header, $this->claims, $this->algo);		
		$validParts = explode('.', $jwt->getJwtAuthReadyString());
		
		$invalidTypeHeader = $this->header;
		$invalidTypeHeader['typ'] = 'invalidTyp';
		$jwtInvalidTyp = Jwt::buildWithNewClaims($invalidTypeHeader, $this->claims, $this->algo);
		
		$nbfJwtClaims = $this->claims;
		$nbfJwtClaims['nbf'] = time() + 1000000;
		$jwtNbf = Jwt::buildWithNewClaims($this->header, $nbfJwtClaims, $this->algo);
		
		$iatJwtClaims = $this->claims;
		$iatJwtClaims['iat'] = time() + 1000000;
		$jwtIat = Jwt::buildWithNewClaims($this->header, $iatJwtClaims, $this->algo);
		
		$expJwtClaims = $this->claims;
		$expJwtClaims['exp'] = time() - 1000000;
		$jwtExp = Jwt::buildWithNewClaims($this->header, $expJwtClaims, $this->algo);
		
		return [
			[NULL, \InvalidArgumentException::class, 'Invalid format'],
			['justTwo.elements', \InvalidArgumentException::class, 'of elements'],
			[
				'notAnArray.' . $validParts[1] . '.' . $validParts[2], 
				\InvalidArgumentException::class, 
				'Unable to decode the elements'
			],
			[
				$validParts[0] . '.notAnArray.' . $validParts[2], 
				\InvalidArgumentException::class, 
				'Unable to decode the elements'
			],
			[
				$jwtInvalidTyp->getJwtAuthReadyString(), 
				\InvalidArgumentException::class, 
				'Header elements are invalid'
			],
			[
				$jwtNbf->getJwtAuthReadyString(), 
				InvalidJwtSignatureException::class, 
				'Cannot handle JWT prior to'
			],
			[
				$jwtIat->getJwtAuthReadyString(), 
				InvalidJwtSignatureException::class, 
				'Cannot handle JWT prior to'
			],
			[
				$jwtExp->getJwtAuthReadyString(), 
				InvalidJwtSignatureException::class, 
				'Expired JWT'
			]
		];
	}
	
	/**
	 * @dataProvider buildFromClaimsFailDataProvider
	 * @depends testBuildFromClaimsWorks
	 */
	public function testBuildFromClaimsThrowsException($jwtString, $exceptionClass, $exceptionMessage) {
		$this->expectException($exceptionClass);
		$this->expectExceptionMessage($exceptionMessage);
		
		Jwt::buildFromClaims($jwtString);
	}
	
	public function testVerifyWorks() {
		$jwt = Jwt::buildWithNewClaims($this->header, $this->claims, $this->algo);
		$jwt->verify([$this->algo]);
		
		// To not be marked as risky just assert true
		$this->assertTrue(TRUE);
	}
	
	public function testVerifyThrowsExceptionWhenInvalidSignature() {
		$jwt = Jwt::buildWithNewClaims($this->header, $this->claims, $this->algo);
		$jwt = Jwt::buildFromClaims($jwt->getJwtAuthReadyString() . 'a');
		
		$this->expectException(InvalidJwtSignatureException::class);
		$this->expectExceptionMessage('Invalid signature');
		
		$jwt->verify([$this->algo]);
	}
}

?>
