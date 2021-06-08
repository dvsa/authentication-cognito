<?php

namespace Dvsa\Authentication\Cognito\Tests;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Dvsa\Authentication\Cognito\Client;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class AttributesAreProvidedInCorrectFormatTest extends TestCase
{
    /**
     * @var CognitoIdentityProviderClient|MockObject
     */
    protected $cognitoIdentityProviderClient;

    protected function setUp(): void
    {
        $this->cognitoIdentityProviderClient = $this->getMockBuilder(CognitoIdentityProviderClient::class)
            ->disableOriginalConstructor()
            ->addMethods(['adminUpdateUserAttributes'])
            ->getMockForAbstractClass();
    }

    /**
     * @dataProvider provideAttributeCombinations
     */
    public function testAttributesFormattedCorrectly(array $expected, array $actual): void
    {
        $this->cognitoIdentityProviderClient
            ->expects($this->once())
            ->method('adminUpdateUserAttributes')
            ->with($this->callback(function (array $arg) use ($actual) {
                return isset($arg['UserAttributes']) && $arg['UserAttributes'] === $actual;
            }));

        $client = new Client($this->cognitoIdentityProviderClient, 'CLIENT_ID', 'CLIENT_SECRET', 'POOL_ID');

        $client->changeAttributes('USERNAME', $expected);
    }

    public function provideAttributeCombinations(): \Generator
    {
        yield [
            ['Key1' => 'Value1', 'Key2' => 'Value2'],
            [
                ['Name' => 'Key1', 'Value' => 'Value1'],
                ['Name' => 'Key2', 'Value' => 'Value2']
            ],
        ];

        yield [
            [],
            []
        ];
    }
}
