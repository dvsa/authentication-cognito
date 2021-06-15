<?php

namespace Dvsa\Authentication\Cognito\Tests;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\Exception\AwsException;
use Dvsa\Authentication\Cognito\Client;
use Dvsa\Contracts\Auth\Exceptions\ClientException;
use PHPUnit\Framework\Constraint\IsAnything;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class ContractExceptionsAreThrownInsteadTest extends TestCase
{
    /**
     * @var CognitoIdentityProviderClient|MockObject
     */
    protected $cognitoIdentityProviderClient;

    protected function setUp(): void
    {
        $this->cognitoIdentityProviderClient = $this->createMock(CognitoIdentityProviderClient::class);
    }

    /**
     * @dataProvider provideAllClientInterfaceMethods
     */
    public function testMethodsWillThrowContractedException(string $method, array $args = []): void
    {
        $this->cognitoIdentityProviderClient
            ->method(new IsAnything)
            ->willThrowException($this->createMock(AwsException::class));

        $this->expectException(ClientException::class);

        $client = new Client($this->cognitoIdentityProviderClient, 'CLIENT_ID', 'CLIENT_SECRET', 'POOL_ID');

        $client->{$method}(...$args);
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
