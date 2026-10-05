<?php

declare(strict_types=1);

namespace Dvsa\Authentication\Cognito\Tests;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\CommandInterface;
use Aws\Credentials\Credentials;
use Aws\Exception\AwsException;
use Aws\MockHandler as AwsMockHandler;
use Dvsa\Authentication\Cognito\Client;
use Dvsa\Contracts\Auth\Exceptions\ClientException;
use PHPUnit\Framework\TestCase;

class ResponseToAuthChallengeValidatesChallengeNameTest extends TestCase
{
    protected AwsMockHandler $mockHandler;

    protected Client $client;

    protected function setUp(): void
    {
        $this->mockHandler = new AwsMockHandler();

        $cognitoIdentityProviderClient = new CognitoIdentityProviderClient([
            'credentials' => new Credentials('AWS_ACCESS_KEY', 'AWS_SECRET_KEY'),
            'region'  => 'us-west-2',
            'version' => 'latest',
            'handler' => $this->mockHandler
        ]);

        $this->client = new Client($cognitoIdentityProviderClient, 'CLIENT_ID', 'CLIENT_SECRET', 'POOL_ID');
    }

    public function testUnknownChallengeNameIsRejectedWithoutCallingAws(): void
    {
        $this->expectException(ClientException::class);
        $this->expectExceptionMessage("Unsupported challenge name 'NOT_A_CHALLENGE'");

        try {
            $this->client->responseToAuthChallenge('NOT_A_CHALLENGE', ['USERNAME' => 'IDENTIFIER'], 'SESSION_TOKEN_0123456789');
        } finally {
            $this->assertCount(0, $this->mockHandler);
        }
    }

    public function testKnownChallengeNameIsSentToAws(): void
    {
        $this->mockHandler->append(function (CommandInterface $cmd) {
            $this->assertSame('NEW_PASSWORD_REQUIRED', $cmd['ChallengeName']);

            return new AwsException('Mock exception', $cmd);
        });

        $this->expectException(ClientException::class);

        $this->client->responseToAuthChallenge('NEW_PASSWORD_REQUIRED', ['USERNAME' => 'IDENTIFIER'], 'SESSION_TOKEN_0123456789');
    }
}
