<?php
namespace tests\algorithm;

use geocata\auth\jwt\algorithm\AbstractRsCryptography;
use geocata\auth\jwt\exception\JwtLibraryCompatibilityException;
use geocata\auth\jwt\algorithm\RS256Cryptography;
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
class AbstractRsCryptographyTest extends \PHPUnit\Framework\TestCase {
    private $privKey;
    private $pubKey;

    /**
     * @return void
     */
    protected function setUp() {
        $privKeyRes = openssl_pkey_new(array(
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ));
        
        $details = openssl_pkey_get_details($privKeyRes);
        
        $this->pubKey = $details['key'];
        openssl_pkey_export($privKeyRes, $privKey);
        $this->privKey = $privKey;
    }

    public function testConstructWorks() {
        $stub = $this->getMockForAbstractClass(AbstractRsCryptography::class, [
            $this->privKey,
            $this->pubKey
        ]);
        
        // Just do this so the test won't show as risky/unfinished
        $this->assertTrue(TRUE);
    }
    
    public function testConstructFailsWhenInvalidEnv() {
        $stub = $this->getMockForAbstractClass(AbstractRsCryptography::class, [], '', FALSE, TRUE,
                TRUE, ['checkEnvCompatibility']);
        
        $stub->expects($this->once())
                ->method('checkEnvCompatibility')
                ->will($this->throwException(new JwtLibraryCompatibilityException('Stub exception.')));
        
        $this->expectException(JwtLibraryCompatibilityException::class);
        
        $stub->__construct($this->privKey, $this->pubKey);
    }
    
    public function constructBadDataProvider() {
        return [
            [NULL, NULL],
            ['invalidPrivKey', $this->pubKey],
            [$this->privKey, 'invalidPubKey']
        ];
    }
    
    /**
     * @dataProvider constructBadDataProvider
     */
    public function testConstructFails($privKey, $pubKey) {
        $this->expectException(\InvalidArgumentException::class);
        
        $this->getMockForAbstractClass(AbstractRsCryptography::class, [$privKey,$pubKey]);
    }
    
    public function testSignWorks() {
        $stub = $this->getMockForAbstractClass(AbstractRsCryptography::class, [
            $this->privKey,
            $this->pubKey
        ]);
        
        $stub->expects($this->once())
                ->method('getHashAlgo')
                ->will($this->returnValue(RS256Cryptography::INTERNAL_ALGORITHM));
        
        $msg = $stub->sign('aMessage');
        
        $this->assertTrue(is_string($msg));
    }
    
    public function testSignFails() {
        $this->expectException(JwtSigningException::class);
        
        $stub = $this->getMockForAbstractClass(AbstractRsCryptography::class, [
            $this->privKey,
            $this->pubKey
        ]);
        
        $stub->expects($this->once())
                ->method('getHashAlgo')
                ->will($this->returnValue('invalid algo'));
        
        $stub->sign('aMessage');
    }
    
    public function testVerifyWorks() {        
        $stub = $this->getMockForAbstractClass(AbstractRsCryptography::class, [
            $this->privKey,
            $this->pubKey
        ]);
        
        $stub->expects($this->any())
                ->method('getHashAlgo')
                ->will($this->returnValue(RS256Cryptography::INTERNAL_ALGORITHM));
        
        $originalMsg = 'Test';
        openssl_sign($originalMsg, $userSignedMessage, $this->privKey, RS256Cryptography::INTERNAL_ALGORITHM);
        
        $stub->verify($originalMsg, $userSignedMessage);
        
        // Just assert something so it won't appear as risky
        $this->assertTrue(TRUE);
    }
    
    public function testVerifyFails() {
        $stub = $this->getMockForAbstractClass(AbstractRsCryptography::class, [
            $this->privKey,
            $this->pubKey
        ]);
        
        $stub->expects($this->any())
                ->method('getHashAlgo')
                ->will($this->returnValue(RS256Cryptography::INTERNAL_ALGORITHM));
        
        // Test data fetched from https://jwt.io/
        $originalMsg = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.TCYt5XsITJX1CxPCT8yAV-TVkIEq_PbChOMqsLfRoPsnsgw5WEuts01mq-pQy7UJiN5mgRxD-WUcX16dUEMGlv50aqzpqh4Qktb3rk-BuQy72IFLOqV0G_zS245-kronKb78cPN25DGlcTwLtjPAYuNzVBAh4vGHSrQyHUdBBPMX';
        $userSignedMessage = $this->urlsafeB64Decode('TCYt5XsITJX1CxPCT8yAV-TVkIEq_PbChOMqsLfRoPsnsgw5WEuts01mq-pQy7UJiN5mgRxD-WUcX16dUEMGlv50aqzpqh4Qktb3rk-BuQy72IFLOqV0G_zS245-kronKb78cPN25DGlcTwLtjPAYuNzVBAh4vGHSrQyHUdBBPMX');
        
        $this->expectException(InvalidJwtSignatureException::class);
        
        $stub->verify($originalMsg, $userSignedMessage);
    }
    
    private function urlsafeB64Decode($input) {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }
}

?>
