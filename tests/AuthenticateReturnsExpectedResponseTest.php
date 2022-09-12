<?php

namespace Dvsa\Authentication\Cognito\Tests;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\Credentials\Credentials;
use Aws\MockHandler as AwsMockHandler;
use Aws\Result;
use Dvsa\Authentication\Cognito\AccessToken;
use Dvsa\Authentication\Cognito\Client;
use Dvsa\Contracts\Auth\AccessTokenInterface;
use Dvsa\Contracts\Auth\Exceptions\ChallengeException;
use Dvsa\Contracts\Auth\Exceptions\ClientException;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Handler\MockHandler as MockHttpHandler;
use GuzzleHttp\HandlerStack;
use PHPUnit\Framework\TestCase;

class AuthenticateReturnsExpectedResponseTest extends TestCase
{
    protected AwsMockHandler $mockHandler;

    protected Client $client;

    protected function setUp(): void
    {
        $this->mockHandler = new AwsMockHandler();

        $awsCredentials = new Credentials('AWS_ACCESS_KEY', 'AWS_SECRET_KEY');

        $cognitoIdentityProviderClient = new CognitoIdentityProviderClient([
            'credentials' => $awsCredentials,
            'region'  => 'us-west-2',
            'version' => 'latest',
            'handler' => $this->mockHandler
        ]);

        $this->client = new Client($cognitoIdentityProviderClient, 'CLIENT_ID', 'CLIENT_SECRET', 'POOL_ID');

        $handlerStack = HandlerStack::create(new MockHttpHandler());
        $httpClient = new HttpClient(['handler' => $handlerStack]);
        $this->client->setHttpClient($httpClient);
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

        // Mock the current time to a constant value to allow a reliable assertion.
        $now = time();
        AccessToken::setTimeNow($now);

        $response = $this->client->authenticate('USERNAME', 'PASSWORD');

        $this->assertInstanceOf(AccessTokenInterface::class, $response);

        // Assert the correct values are set on the `$response` object.
        $this->assertEquals('ACCESS_TOKEN', $response->getToken());
        $this->assertEquals('REFRESH_TOKEN', $response->getRefreshToken());
        $this->assertEquals('ID_TOKEN', $response->getIdToken());
        $this->assertEquals($now + 60, $response->getExpires());
    }

    public function testAuthenticateActionWillThrowChallengeExceptionWhenReturnedAChallenge(): void
    {
        $this->mockHandler->append(new Result([
            'ChallengeName' => 'CHALLENGE_NAME',
            'ChallengeParameters' => ['CHALLENGE_PARAM_1', 'CHALLENGE_PARAM_2'],
            'Session' => 'SESSION',
        ]));

        $this->expectException(ChallengeException::class);

        $this->client->authenticate('USERNAME', 'PASSWORD');
    }

    public function testAuthenticateActionWillThrowExceptionWhenMalformedResponse(): void
    {
        $this->mockHandler->append(new Result([
            'UNKNOWN_RESPONSE'
        ]));

        $this->expectException(ClientException::class);

        $this->client->authenticate('USERNAME', 'PASSWORD');
    }
}
