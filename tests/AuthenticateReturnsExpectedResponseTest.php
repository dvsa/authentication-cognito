<?php

namespace Dvsa\Authentication\Cognito\Tests;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\Credentials\Credentials;
use Aws\MockHandler;
use Aws\Result;
use Dvsa\Authentication\Cognito\Client;
use Dvsa\Contracts\Auth\AccessTokenInterface;
use Dvsa\Contracts\Auth\ChallengeException;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class AuthenticateReturnsExpectedResponseTest extends TestCase
{
    /**
     * @var CognitoIdentityProviderClient|MockObject
     */
    protected $cognitoIdentityProviderClient;

    /**
     * @var MockHandler
     */
    protected $mockHandler;

    protected function setUp(): void
    {
        $this->mockHandler = new MockHandler();

        $awsCredentials = new Credentials('AWS_ACCESS_KEY', 'AWS_SECRET_KEY');

        $this->cognitoIdentityProviderClient = new CognitoIdentityProviderClient([
            'credentials' => $awsCredentials,
            'region'  => 'us-west-2',
            'version' => 'latest',
            'handler' => $this->mockHandler
        ]);
    }

    public function testAuthenticateActionWillReturnAccessToken(): void
    {
        $this->mockHandler->append(
            new Result([
                'AuthenticationResult' => [
                    'AccessToken' => 'ACCESS_TOKEN',
                    'IdToken' => 'ID_TOKEN',
                    'RefreshToken' => 'REFRESH_TOKEN',
                    'ExpiresIn' => 60,
                    'TokenType' => 'Bearer',
                ]
            ])
        );

        $client = new Client($this->cognitoIdentityProviderClient, 'CLIENT_ID', 'CLIENT_SECRET', 'POOL_ID');

        $response = $client->authenticate('USERNAME', 'PASSWORD');

        $this->assertInstanceOf(AccessTokenInterface::class, $response);
    }

    public function testAuthenticateActionWillThrowExceptionWhenReturnedAChallenge(): void
    {
        $this->mockHandler->append(new Result([
            'ChallengeName' => 'CHALLENGE_NAME',
            'ChallengeParameters' => ['CHALLENGE_PARAM_1', 'CHALLENGE_PARAM_2'],
            'Session' => 'SESSION',
        ]));

        $client = new Client($this->cognitoIdentityProviderClient, 'CLIENT_ID', 'CLIENT_SECRET', 'POOL_ID');

        $this->expectException(ChallengeException::class);

        $client->authenticate('USERNAME', 'PASSWORD');
    }
}
