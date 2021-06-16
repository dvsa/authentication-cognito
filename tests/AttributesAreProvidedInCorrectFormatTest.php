<?php

namespace Dvsa\Authentication\Cognito\Tests;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\CommandInterface;
use Aws\Credentials\Credentials;
use Aws\MockHandler;
use Aws\Result;
use Dvsa\Authentication\Cognito\Client;
use PHPUnit\Framework\TestCase;

class AttributesAreProvidedInCorrectFormatTest extends TestCase
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
     * @dataProvider provideAttributeCombinations
     */
    public function testAttributesFormattedCorrectly(array $raw, array $expected): void
    {
        // You can provide a function to invoke; here we throw a mock exception
        $this->mockHandler->append(function (CommandInterface $cmd) use ($expected) {
            $this->assertEquals($expected, $cmd['UserAttributes']);

            return new Result();
        });

        $this->client->changeAttributes('USERNAME', $raw);
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
            ['Key1' => false, 'Key2' => true],
            [
                ['Name' => 'Key1', 'Value' => 'false'],
                ['Name' => 'Key2', 'Value' => 'true']
            ],
        ];

        yield [
            [],
            []
        ];
    }
}
