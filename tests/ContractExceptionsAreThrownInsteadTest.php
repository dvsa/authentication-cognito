<?php

namespace Dvsa\Authentication\Cognito\Tests;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\CommandInterface;
use Aws\Credentials\Credentials;
use Aws\Exception\AwsException;
use Aws\MockHandler;
use Dvsa\Authentication\Cognito\Client;
use Dvsa\Contracts\Auth\Exceptions\ClientException;
use PHPUnit\Framework\TestCase;

class ContractExceptionsAreThrownInsteadTest extends TestCase
{
    /**
     * @var MockHandler
     */
    protected $mockHandler;

    /**
     * @var Client
     */
    protected $client;

    protected function setUp(): void
    {
        $this->mockHandler = new MockHandler();

        $awsCredentials = new Credentials('AWS_ACCESS_KEY', 'AWS_SECRET_KEY');

        $cognitoIdentityProviderClient = new CognitoIdentityProviderClient([
            'credentials' => $awsCredentials,
            'region'  => 'us-west-2',
            'version' => 'latest',
            'handler' => $this->mockHandler
        ]);

        $this->client = new Client($cognitoIdentityProviderClient, 'CLIENT_ID', 'CLIENT_SECRET', 'POOL_ID');
    }

    /**
     * @dataProvider provideAllClientInterfaceMethods
     */
    public function testMethodsWillThrowContractedException(string $method, array $args = []): void
    {
        $this->mockHandler->append(function (CommandInterface $cmd) {
            return new AwsException('Mock exception', $cmd);
        });

        $this->expectException(ClientException::class);

        $this->client->{$method}(...$args);
    }

    public function provideAllClientInterfaceMethods(): \Generator
    {
        yield ['authenticate', ['IDENTIFIER', 'PASSWORD']];
        yield ['register', ['IDENTIFIER', 'PASSWORD', []]];
        yield ['changePassword', ['IDENTIFIER', 'NEW_PASSWORD']];
        yield ['changeAttribute', ['IDENTIFIER', 'KEY', 'VALUE']];
        yield ['changeAttributes', ['IDENTIFIER', []]];
        yield ['enableUser', ['IDENTIFIER']];
        yield ['disableUser', ['IDENTIFIER']];
        yield ['getUserByIdentifier', ['IDENTIFIER']];
    }
}
