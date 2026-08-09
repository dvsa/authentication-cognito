[aws-sdk]: https://github.com/aws/aws-sdk-php
[composer]: https://getcomposer.org/
[psr-6]: https://www.php-fig.org/psr/psr-6/

DVSA Cognito Authentication Wrapper
===================================
A thin authentication wrapper around the [aws-sdk][aws-sdk], focusing on the Cognito endpoints.

Installing
----------
The recommended way to install is through [Composer][composer].
```
composer require dvsa/authentication-cognito
```

Usage
-----

```php
<?php

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\Credentials\Credentials;
use Dvsa\Authentication\Cognito\Client;

# Variables below must be replaced by their respective values.
$accessKey = 'AWS_ACCESS_KEY';
$secret = 'AWS_SECRET';

$clientId = 'CLIENT_ID';
$clientSecret = 'CLIENT_SECRET';
$poolId = 'POOL_ID';

# https://docs.aws.amazon.com/aws-sdk-php/v3/api/class-Aws.Credentials.Credentials.html#___construct
$awsCredentials = new Credentials($accessKey, $secret);

# https://docs.aws.amazon.com/aws-sdk-php/v3/api/class-Aws.AwsClient.html#___construct
$awsClient = new CognitoIdentityProviderClient([
    'credentials' => $awsCredentials,
    'version' => '2016-04-18',
    'region' => 'eu-west-2'
]);

return new Client(
    $awsClient,
    $clientId,
    $clientSecret,
    $poolId
);
```

Caching the JSON Web Key Set
----------------------------
Verifying a token requires Cognito's public signing keys. With no cache configured the client
re-downloads the JWKS on **every** `decodeToken()` call — PHP shares nothing between requests, so
on a web application that is an outbound HTTPS round trip to Cognito per authenticated request.

Pass any [PSR-6][psr-6] cache pool to avoid it:

```php
$client = new Client(
    $awsClient,
    $clientId,
    $clientSecret,
    $poolId,
    $cachePool # any Psr\Cache\CacheItemPoolInterface
);
```

Keys are looked up by key id and only re-fetched when an unrecognised one turns up, so Cognito key
rotation is still picked up automatically — there is nothing to invalidate by hand.

### Tuning

The defaults are chosen to be safe; most applications will not need to change them.

```php
$client->setCacheOptions(
    expiresAfter: 3600, # seconds. null defers to the pool's own default lifetime
    rateLimit: true     # cap JWKS re-fetches at 10 per minute
);
```

- **`expiresAfter`** bounds how long a cached JWKS is trusted. A key Cognito has revoked is still a
  *known* key id, so it never triggers the unknown-key re-fetch that would evict it; without an
  expiry the client would go on accepting tokens signed by that key. Passing `null` hands the
  decision to your pool, which for some implementations means the entry never expires.
- **`rateLimit`** caps re-fetches at 10 per minute. A cache miss is driven by the key id in the
  incoming token, which is attacker-controlled, so leaving this off lets a stream of tokens bearing
  unknown key ids become a stream of outbound calls to Cognito. The trade-off is that once the
  budget is spent, tokens with an unrecognised key id are rejected until the window clears.

### A note on trust

The cached JWKS is what signature verification is performed against, so anything able to write to
that cache can influence which tokens are accepted. Back it with a store your application trusts to
the same degree it trusts its own session storage.

Contributing
------------
Please refer to our [Contribution Guide](/CONTRIBUTING.md) and [Contributor Code of Conduct](/CODE_OF_CONDUCT.md).
