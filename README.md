
# auth

A collection of authentication libraries for PHP. For now it only includes a JWT library.  
  
**Composer install :**  
```
{
    "repositories": [
        {
            "url": "https://github.com/geocata/auth.git",
            "type": "git"
        }
    ],
    "require": {
        "geocata/auth": "~1.0"
    }
}
```  
**Usage :**  
```  
<?php  
use geocata\auth\jwt;  
use geocata\auth\jwt\algorithm\HS256Cryptography;  
  
// Set the cryptographic algorithm to be used. You can find more algorithms in the
// geocata\auth\jwt\algorithm namespace. You can also add more algorithms there if you want,
// or build your own algorithm classes by extending the base AbstractCryptography class
$algo = new HS256Cryptography('aKey');

$header = [
    'alg' => HS256Cryptography::JWT_ALGORITHM, 
    'typ' => 'jwt'
];

$claims = [
    'usr' => 'test', 
    'msg' => 'amsg',
    'nbf' => time() - 10, // Not before. Token should not be used before timestamp. 
                          // Check Jwt::CLOCK_SKEW. Adjust it as you want
    'iat' => time() - 10, // When the token was issued. Same as nbf. 
                          // Check Jwt::CLOCK_SKEW. Adjust it as you want
    'exp' => time() + 30  // When the token expires. It should not be used after this timestamp
                          // Check Jwt::CLOCK_SKEW. Adjust it as you want
];

try {
    // Build a new Jwt instance with the given new claims
    $jwtWithNewClaims = Jwt::buildWithNewClaims($header, $claims, $algo);
    
    // Fetch the generated url safe token string ready for authentication
    $tokenString = $jwtWithNewClaims->getJwtAuthReadyString();
    
    // Build a new Jwt instance from an existing token string
    $jwtFromClaims = Jwt::buildFromClaims($tokenString);
    
    // Access the token header and claims
    $tokenHeader = $jwtFromClaims->getHeader();
    $tokenClaims = $jwtFromClaims->getClaims();
    
    // Verify that the jwt claims built from a string are authentic by passing an array of allowed
    // algorithms to be used. You can use any number of algorithms
    $jwtFromClaims->verify([$algo]);
} catch (\Exception $ex) {
    // Do something with the thrown exception
    throw $ex;
}
```
