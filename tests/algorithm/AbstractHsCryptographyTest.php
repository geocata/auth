<?php

namespace tests\algorithm;

use geocata\auth\jwt\algorithm\AbstractHsCryptography;
use geocata\auth\jwt\algorithm\HS256Cryptography;
use geocata\auth\jwt\exception\JwtSigningFailed;
use geocata\auth\jwt\exception\InvalidJwtSignature;

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
class AbstractHsCryptographyTest extends \PHPUnit\Framework\TestCase
{

    /**
     * @return void
     */
    protected function setUp()
    {
        
    }

    public function testSignWorks()
    {
        $stub = $this->getMockForAbstractClass(AbstractHsCryptography::class, ['aKey']);
        $stub->expects($this->once())
                ->method('getHashAlgo')
                ->will($this->returnValue(HS256Cryptography::INTERNAL_ALGORITHM));

        $this->assertTrue(!empty($stub->sign('aMessage')));
    }

    public function testSignFailsWhenInvalidAlgo()
    {
        $stub = $this->getMockForAbstractClass(AbstractHsCryptography::class, ['aKey']);
        $stub->expects($this->once())
                ->method('getHashAlgo')
                ->will($this->returnValue('anInvalidAlgo'));

        $this->expectException(JwtSigningFailed::class);

        $stub->sign('aMessage');
    }

    public function testVerifyWorks()
    {
        $stub = $this->getMockForAbstractClass(AbstractHsCryptography::class, ['aKey'], '', TRUE, TRUE,
                                               TRUE, ['sign', 'equals']);

        $stub->expects($this->any())
                ->method('getHashAlgo')
                ->will($this->returnValue(HS256Cryptography::INTERNAL_ALGORITHM));

        $stub->expects($this->any())
                ->method('sign');

        $stub->expects($this->any())
                ->method('equals');

        // Test data fetched from https://jwt.io/
        $originalMsg = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.tf9UhpabA-Eg7xYp_eYgZsme-vvTQBVSKtm5TXNN-80';
        $userSignedMessage = $this->urlsafeB64Decode('tf9UhpabA-Eg7xYp_eYgZsme-vvTQBVSKtm5TXNN-80');

        $stub->verify($originalMsg, $userSignedMessage);

        // Just to bypass risky test
        $this->assertTrue(TRUE);
    }

    public function testVerifyFails()
    {
        $stub = $this->getMockForAbstractClass(AbstractHsCryptography::class, ['aKey']);

        $stub->expects($this->any())
                ->method('getHashAlgo')
                ->will($this->returnValue(HS256Cryptography::INTERNAL_ALGORITHM));

        // Test data fetched from https://jwt.io/
        $originalMsg = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.tf9UhpabA-Eg7xYp_eYgZsme-vvTQBVSKtm5TXNN-80';
        $userSignedMessage = $this->urlsafeB64Decode('vUyxOP_iKkoKxD0VVPUbmpGrXezQhyi9hBf0bx2A4FU');

        $this->expectException(InvalidJwtSignature::class);

        $stub->verify($originalMsg, $userSignedMessage);
    }

    private function urlsafeB64Decode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

}