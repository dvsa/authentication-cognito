[aws-sdk]: https://github.com/aws/aws-sdk-php
[composer]: https://getcomposer.org/

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

Contributing
------------
Please refer to our [Contribution Guide](/CONTRIBUTING.md) and [Contributor Code of Conduct](/CODE_OF_CONDUCT.md).
